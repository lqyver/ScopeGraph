from scopegraph.tooling.adapters.alterx import AlterxAdapter
from scopegraph.tooling.adapters.dnsx import DnsxAdapter
from scopegraph.tooling.adapters.httpx import HttpxAdapter
from scopegraph.tooling.adapters.katana import KatanaAdapter
from scopegraph.tooling.adapters.naabu import NaabuAdapter
from scopegraph.tooling.adapters.nmap import NmapAdapter
from scopegraph.tooling.adapters.nuclei import NucleiAdapter
from scopegraph.tooling.adapters.puredns import PurednsAdapter
from scopegraph.tooling.adapters.screenshot import ScreenshotAdapter
from scopegraph.tooling.adapters.subfinder import SubfinderAdapter

ADAPTERS = {
    adapter.manifest.name: adapter
    for adapter in (
        SubfinderAdapter(),
        AlterxAdapter(),
        PurednsAdapter(),
        DnsxAdapter(),
        NaabuAdapter(),
        NmapAdapter(),
        NucleiAdapter(),
        HttpxAdapter(),
        KatanaAdapter(),
        ScreenshotAdapter(),
    )
}

__all__ = [
    "ADAPTERS",
    "AlterxAdapter",
    "DnsxAdapter",
    "HttpxAdapter",
    "KatanaAdapter",
    "NaabuAdapter",
    "NmapAdapter",
    "NucleiAdapter",
    "PurednsAdapter",
    "ScreenshotAdapter",
    "SubfinderAdapter",
]
