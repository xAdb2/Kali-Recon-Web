"""Docker runner cancellation / orphan cleanup with a mocked Docker client."""
from recon.services.docker_runner import cleanup_orphans, stop_task_containers


class FakeContainer:
    def __init__(self, cid, labels):
        self.id = cid
        self.labels = labels
        self.killed = False
        self.removed = False

    def kill(self):
        self.killed = True

    def remove(self, force=False):
        self.removed = True


class FakeContainers:
    def __init__(self, containers):
        self._c = containers

    def list(self, all=False, filters=None):
        key, _, val = filters["label"].partition("=")
        return [c for c in self._c if c.labels.get(key) == val]


class FakeClient:
    def __init__(self, containers):
        self.containers = FakeContainers(containers)


def test_stop_task_containers_kills_only_matching_label():
    target = FakeContainer("a", {"kalirecon.task": "task-123", "kalirecon": "1"})
    other = FakeContainer("b", {"kalirecon.task": "task-999", "kalirecon": "1"})
    client = FakeClient([target, other])

    stopped = stop_task_containers("task-123", client=client)

    assert stopped == 1
    assert target.killed and target.removed
    assert not other.killed


def test_cleanup_orphans_removes_all_app_containers():
    c1 = FakeContainer("a", {"kalirecon": "1"})
    c2 = FakeContainer("b", {"kalirecon": "1"})
    client = FakeClient([c1, c2])

    removed = cleanup_orphans(client=client)

    assert removed == 2
    assert c1.removed and c2.removed
