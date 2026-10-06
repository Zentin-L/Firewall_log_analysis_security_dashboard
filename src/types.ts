export type FirewallAction = 'ALLOW' | 'BLOCK' | 'DROP' | 'REJECT';

export type LogSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type NetworkProtocol = 'TCP' | 'UDP' | 'ICMP' | 'GRE' | 'ESP' | 'OTHER';

export type FirewallType =
  | 'AWS_VPC'
  | 'PALO_ALTO'
  | 'CISCO_ASA'
  | 'IPTABLES'
  | 'PFSENSE'
  | 'CLOUDFLARE'
  | 'FORTINET'
  | 'CUSTOM_JSON'
  | 'SYSLOG';

export type ThreatCategory =
  | 'BENIGN'
  | 'PORT_SCAN'
  | 'BRUTE_FORCE'
  | 'EXPLOIT_PROBE'
  | 'DDOS_FLOOD'
  | 'GEO_SANCTION'
  | 'MALWARE_C2'
  | 'DNS_TUNNEL'
  | 'UNAUTHORIZED_ACCESS';

export interface FirewallLog {
  id: string;
  timestamp: string; // ISO string
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: NetworkProtocol;
  action: FirewallAction;
  severity: LogSeverity;
  ruleName: string;
  firewallType: FirewallType;
  interface?: string;
  bytes: number;
  packets: number;
  tcpFlags?: string[];
  sourceCountry?: string; // 2-letter ISO code (e.g., 'US', 'DE')
  sourceCountryName?: string;
  sourceCity?: string;
  sourceAsn?: string;
  threatCategory: ThreatCategory;
  threatDescription?: string;
  rawLog: string;
}

export interface SecurityAlert {
  id: string;
  title: string;
  category: ThreatCategory;
  severity: LogSeverity;
  sourceIp: string;
  targetPorts: number[];
  eventCount: number;
  firstSeen: string;
  lastSeen: string;
  mitreTechnique?: string;
  description: string;
  recommendedAction: string;
  status: 'ACTIVE' | 'INVESTIGATING' | 'RESOLVED' | 'IGNORED';
}

export interface FilterState {
  searchQuery: string;
  action: string;
  protocol: string;
  severity: string;
  threatCategory: string;
  timeRange: 'all' | '15m' | '1h' | '6h' | '24h';
  country: string;
  selectedIp?: string;
  selectedPort?: number;
}

export interface DashboardStats {
  totalLogs: number;
  allowedCount: number;
  blockedCount: number;
  droppedCount: number;
  rejectedCount: number;
  blockRate: number; // percentage
  uniqueSourceIps: number;
  uniqueDestIps: number;
  totalBytes: number;
  totalPackets: number;
  activeThreatCount: number;
  criticalThreatCount: number;
}

export interface TimelineDataPoint {
  timeLabel: string;
  timestamp: number;
  allowed: number;
  blocked: number;
  dropped: number;
  total: number;
  bytes: number;
}

export interface ProtocolStat {
  protocol: string;
  count: number;
  percentage: number;
  bytes: number;
  color: string;
}

export interface TargetPortStat {
  port: number;
  service: string;
  count: number;
  blockedCount: number;
  percentage: number;
}

export interface TopAttackerStat {
  ip: string;
  country: string;
  countryName: string;
  asn: string;
  hits: number;
  blockedHits: number;
  topPort: number;
  threatCategory: ThreatCategory;
  severity: LogSeverity;
  lastSeen: string;
}

export interface GeoThreatStat {
  countryCode: string;
  countryName: string;
  totalEvents: number;
  blockedEvents: number;
  threatScore: number;
  topThreat: ThreatCategory;
}

export interface AiTriageResult {
  summary: string;
  threatLevel: LogSeverity;
  mitreAttack?: {
    tactic: string;
    technique: string;
    id: string;
  };
  rootCauseAnalysis: string;
  attackerProfile: {
    origin: string;
    intent: string;
    sophistication: 'Script Kiddie' | 'Automated Botnet' | 'Targeted APT' | 'Commercial Scanner' | 'Unknown';
  };
  recommendedMitigation: string[];
  firewallRules: {
    iptables?: string;
    awsWaf?: string;
    ciscoAcl?: string;
    pfsense?: string;
    cloudflare?: string;
  };
}

export interface ConnectorConfig {
  sourceType: FirewallType;
  name: string;
  description: string;
  sampleFormat: string;
}
