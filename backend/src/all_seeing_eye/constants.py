from enum import StrEnum

class Status(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"

FINISHED = {Status.OK, Status.PARTIAL, Status.FAILED}

class ParseStatus(StrEnum):
    PENDING = "pending"
    OK = "ok"
    EMPTY = "empty"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"

class OSType(StrEnum):
    IOS = "ios"
    IOSXE = "iosxe"
    NXOS = "nxos"
    FORTIOS = "fortios"

class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Actor(StrEnum):
    API = "api"
    WORKER = "worker"
    COLLECTOR = "collector"
    PARSER = "parser"
    ANALYZER = "analyzer"
    SCANNER = "scanner"

class Action(StrEnum):
    JOB_CREATE = "job_create"
    JOB_FINISH = "job_finish"
    DEVICE_LOGIN = "device_login"
    COLLECT = "collect"
    PARSE = "parse"
    ANALYZE = "analyze"
    SCAN = "scan"

class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"

class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"

class Method(StrEnum):
    LLM = "llm"
    RULE = "rule"
    BOTH = "both"