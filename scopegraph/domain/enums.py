from enum import StrEnum


class ProjectStatus(StrEnum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class ScanProfile(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    CUSTOM = "custom"


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"


class ScopeRuleType(StrEnum):
    DOMAIN = "DOMAIN"
    ROOT_DOMAIN = "ROOT_DOMAIN"
    IP = "IP"
    CIDR = "CIDR"
    URL = "URL"


class ScopeAction(StrEnum):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class ScopeSource(StrEnum):
    USER = "USER"
    AUTO_CONFIRMED = "AUTO_CONFIRMED"


class AssetType(StrEnum):
    COMPANY = "company"
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    SERVICE = "service"
    CERTIFICATE = "certificate"
    ICP_RECORD = "icp_record"


class ScopeStatus(StrEnum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    EXCLUDED = "EXCLUDED"
    PENDING_REVIEW = "PENDING_REVIEW"
    THIRD_PARTY = "THIRD_PARTY"
    CDN_SHARED = "CDN_SHARED"
    UNKNOWN = "UNKNOWN"


class OwnershipStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    PENDING_REVIEW = "PENDING_REVIEW"
    WEAK_RELATION = "WEAK_RELATION"
    THIRD_PARTY = "THIRD_PARTY"
    REJECTED = "REJECTED"


class RelationType(StrEnum):
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    CNAME_TO = "CNAME_TO"
    HOSTS_SERVICE = "HOSTS_SERVICE"
    SERVES_WEBSITE = "SERVES_WEBSITE"
    REDIRECTS_TO = "REDIRECTS_TO"
    PRESENTS_CERTIFICATE = "PRESENTS_CERTIFICATE"
    HAS_ICP_RECORD = "HAS_ICP_RECORD"
    OFFICIAL_LINK_TO = "OFFICIAL_LINK_TO"
    DISCOVERED_FROM = "DISCOVERED_FROM"
    THIRD_PARTY_HOSTED_BY = "THIRD_PARTY_HOSTED_BY"
    CLUSTERED_WITH = "CLUSTERED_WITH"


class DNSRecordType(StrEnum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    PTR = "PTR"


class IPClassification(StrEnum):
    OWNED = "OWNED"
    CLOUD_SERVER = "CLOUD_SERVER"
    SHARED_HOSTING = "SHARED_HOSTING"
    CDN_WAF = "CDN_WAF"
    UNKNOWN = "UNKNOWN"
    PRIVATE_RESERVED = "PRIVATE_RESERVED"


class TransportProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class PortState(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    UNKNOWN = "UNKNOWN"


class EndpointKind(StrEnum):
    PAGE = "PAGE"
    JAVASCRIPT = "JAVASCRIPT"
    XHR = "XHR"
    WEBSOCKET = "WEBSOCKET"
    ROBOTS = "ROBOTS"
    SITEMAP = "SITEMAP"
    API = "API"
    EXTERNAL_LINK = "EXTERNAL_LINK"


class ICPRecordKind(StrEnum):
    ICP = "ICP"
    PUBLIC_SECURITY = "PUBLIC_SECURITY"


class ICPAssociationStatus(StrEnum):
    PAGE_DIRECT = "PAGE_DIRECT"
    ROOT_DOMAIN_INFERRED = "ROOT_DOMAIN_INFERRED"
    SUBJECT_MATCH = "SUBJECT_MATCH"
    RELATED_SUBJECT = "RELATED_SUBJECT"
    SUBJECT_CONFLICT = "SUBJECT_CONFLICT"
    NOT_FOUND = "NOT_FOUND"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PENDING_MANUAL_VERIFY = "PENDING_MANUAL_VERIFY"
    HISTORICAL = "HISTORICAL"


class EnterpriseDiscoveryStatus(StrEnum):
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILED = "FAILED"


class CandidateRootStatus(StrEnum):
    SUGGESTED_CONFIRM = "SUGGESTED_CONFIRM"
    HIGH_PROBABILITY = "HIGH_PROBABILITY"
    PENDING_REVIEW = "PENDING_REVIEW"
    THIRD_PARTY = "THIRD_PARTY"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


class ReviewResourceType(StrEnum):
    ASSET = "ASSET"
    CANDIDATE_ROOT_DOMAIN = "CANDIDATE_ROOT_DOMAIN"


class ReviewDecision(StrEnum):
    CONFIRM = "CONFIRM"
    ADD_TO_SCOPE = "ADD_TO_SCOPE"
    EXCLUDE = "EXCLUDE"
    MARK_THIRD_PARTY = "MARK_THIRD_PARTY"
    DEFER = "DEFER"


class FindingStatus(StrEnum):
    UNVERIFIED = "UNVERIFIED"
    POTENTIAL = "POTENTIAL"
    REPRODUCIBLE = "REPRODUCIBLE"
    MANUALLY_VERIFIED = "MANUALLY_VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ExportStatus(StrEnum):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class ExportFormat(StrEnum):
    XLSX = "xlsx"
    CSV = "csv"
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"


class ExportScope(StrEnum):
    CONFIRMED = "confirmed"
    CONFIRMED_AND_HIGH = "confirmed-and-high"
    ALL_CANDIDATES = "all-candidates"
    LIVE_WEBSITES = "live-websites"
    FINDINGS_ONLY = "findings-only"
