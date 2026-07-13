"""Task creation form with target validation and expert-command handling."""
from __future__ import annotations

from django import forms
from django.conf import settings

from .constants import SELECTABLE_TOOLS, CommandMode, Profile
from .services.target import TargetValidationError, parse_target
from .services.workflow import WEB_TOOLS, preview_context
from .tools import get_plugin
from .tools.base import ExpertCommandError, sanitize_display

_TOOL_LABELS = {
    "nmap_ports": "Nmap 連接埠探索",
    "nmap_services": "Nmap 服務辨識",
    "http_probe": "HTTP 基線探測",
    "whatweb": "WhatWeb 指紋",
    "tls": "TLS 憑證檢查",
    "dirsearch": "Dirsearch 內容探索",
    "nuclei": "Nuclei 偵察",
}


class ScanTaskForm(forms.Form):
    name = forms.CharField(label="任務名稱", max_length=200)
    target_ip = forms.CharField(label="目標 IP", max_length=64)
    target_url = forms.CharField(
        label="目標 URL（選填，Nmap-only 可留空）",
        max_length=2000,
        required=False,
    )
    profile = forms.ChoiceField(label="掃描設定檔", choices=Profile.choices,
                                initial=Profile.SAFE)
    tools = forms.MultipleChoiceField(
        label="偵察工具",
        choices=[(t, _TOOL_LABELS[t]) for t in SELECTABLE_TOOLS],
        widget=forms.CheckboxSelectMultiple,
    )
    rate_limit = forms.IntegerField(label="請求速率上限", min_value=1, initial=50)
    max_duration = forms.IntegerField(
        label="任務最長執行秒數", min_value=60, initial=3600
    )
    authorized = forms.BooleanField(
        label="我確認已獲得對此目標進行偵察的授權",
        required=True,
    )

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.parsed = None
        self.tool_config: dict = {}
        self.expert_enabled = bool(
            settings.KALIRECON["ENABLE_EXPERT_COMMANDS"]
            and user is not None
            and user.is_superuser
        )

    def clean_rate_limit(self):
        value = self.cleaned_data["rate_limit"]
        max_rate = settings.KALIRECON["MAX_RATE"]
        if value > max_rate:
            raise forms.ValidationError(f"速率上限不可超過 {max_rate}。")
        return value

    def clean(self):
        cleaned = super().clean()
        ip = cleaned.get("target_ip", "")
        url = cleaned.get("target_url", "") or ""
        try:
            parsed = parse_target(ip, url)
        except TargetValidationError as exc:
            raise forms.ValidationError(str(exc)) from exc
        self.parsed = parsed

        tools = cleaned.get("tools", []) or []
        if set(tools) & WEB_TOOLS and not parsed.has_url:
            raise forms.ValidationError("選擇 Web 類工具時必須提供有效的目標 URL。")
        if "tls" in tools and parsed.has_url and not parsed.is_https:
            self.add_error("tools", "TLS 檢查僅適用於 https 目標。")

        # Per-tool command mode / expert command.
        profile = cleaned.get("profile", Profile.SAFE)
        rate = cleaned.get("rate_limit", 50)
        config: dict = {}
        for tool in tools:
            mode = CommandMode.DEFAULT
            command = ""
            if self.expert_enabled:
                raw_mode = self.data.get(f"mode_{tool}", CommandMode.DEFAULT)
                if raw_mode == CommandMode.EXPERT:
                    mode = CommandMode.EXPERT
                    command = (self.data.get(f"expert_{tool}", "") or "").strip()
            if mode == CommandMode.EXPERT:
                if not command:
                    self.add_error(None, f"{_TOOL_LABELS[tool]}：進階指令不可為空。")
                    continue
                plugin = get_plugin(tool)
                ctx = preview_context(parsed, profile, rate, tool)
                try:
                    argv = plugin.validate_expert(command, None, None, ctx)
                except ExpertCommandError as exc:
                    self.add_error(None, f"{_TOOL_LABELS[tool]}：{exc}")
                    continue
                config[tool] = {
                    "mode": CommandMode.EXPERT,
                    "command": command,
                    "normalized": sanitize_display(argv),
                }
            else:
                config[tool] = {"mode": CommandMode.DEFAULT}
        self.tool_config = config
        return cleaned
