"""Parse Nmap XML output into structured service dicts.

Robust against malformed/truncated XML: partial data is returned where
possible and malformed documents raise ``NmapParseError`` instead of crashing
the workflow.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET


class NmapParseError(ValueError):
    pass


def parse_nmap_xml(xml_text: str) -> list[dict]:
    if not xml_text or not xml_text.strip():
        raise NmapParseError("Nmap XML 為空。")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapParseError(f"Nmap XML 解析失敗：{exc}") from exc

    services: list[dict] = []
    for host in root.iter("host"):
        addr = ""
        for address in host.findall("address"):
            if address.get("addrtype") in {"ipv4", "ipv6"}:
                addr = address.get("addr", "")
                break
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            try:
                port_num = int(port.get("portid", "0"))
            except (TypeError, ValueError):
                continue
            svc = port.find("service")
            entry = {
                "ip": addr,
                "port": port_num,
                "transport": port.get("protocol", "tcp"),
                "service_name": "",
                "product": "",
                "version": "",
                "extra_info": "",
            }
            if svc is not None:
                entry["service_name"] = svc.get("name", "") or ""
                entry["product"] = svc.get("product", "") or ""
                entry["version"] = svc.get("version", "") or ""
                entry["extra_info"] = svc.get("extrainfo", "") or ""
            services.append(entry)
    return services


def extract_open_ports(xml_text: str) -> list[int]:
    return sorted({s["port"] for s in parse_nmap_xml(xml_text)})
