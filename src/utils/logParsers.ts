import { FirewallAction, FirewallLog, FirewallType, LogSeverity, NetworkProtocol, ThreatCategory } from '../types';
import { lookupIpGeo } from './geoData';

// Generates an auto-increment or random ID
let counter = 1000;
export function generateLogId(): string {
  return `log-${Date.now()}-${counter++}`;
}

export function detectProtocolNumber(num: string | number): NetworkProtocol {
  const n = typeof num === 'string' ? parseInt(num, 10) : num;
  switch (n) {
    case 6:
      return 'TCP';
    case 17:
      return 'UDP';
    case 1:
      return 'ICMP';
    case 47:
      return 'GRE';
    case 50:
      return 'ESP';
    default:
      if (typeof num === 'string') {
        const upper = num.toUpperCase();
        if (upper.includes('TCP')) return 'TCP';
        if (upper.includes('UDP')) return 'UDP';
        if (upper.includes('ICMP')) return 'ICMP';
      }
      return 'OTHER';
  }
}

export function evaluateThreat(
  action: FirewallAction,
  destPort: number,
  protocol: NetworkProtocol,
  flags: string[] = [],
  bytes = 0
): { category: ThreatCategory; severity: LogSeverity; description: string } {
  // Known vulnerable / high-target ports
  const isPortScan = flags.includes('SYN') && !flags.includes('ACK') && action !== 'ALLOW';
  const isRdpSsh = (destPort === 22 || destPort === 3389 || destPort === 23) && action !== 'ALLOW';
  const isDatabaseProbe = (destPort === 1433 || destPort === 3306 || destPort === 5432 || destPort === 27017 || destPort === 6379) && action !== 'ALLOW';
  const isSmbProbe = (destPort === 445 || destPort === 139) && action !== 'ALLOW';
  const isDdos = (bytes > 50000 || flags.includes('SYN_FLOOD')) && action !== 'ALLOW';

  if (isDdos) {
    return {
      category: 'DDOS_FLOOD',
      severity: 'CRITICAL',
      description: 'High-volume packet flood detected matching volumetric DDoS fingerprint',
    };
  }

  if (isSmbProbe) {
    return {
      category: 'EXPLOIT_PROBE',
      severity: 'HIGH',
      description: 'SMB probing activity detected (potential EternalBlue/WannaCry vector)',
    };
  }

  if (isDatabaseProbe) {
    return {
      category: 'UNAUTHORIZED_ACCESS',
      severity: 'HIGH',
      description: `Direct database connection attempt blocked on port ${destPort}`,
    };
  }

  if (isRdpSsh) {
    return {
      category: 'BRUTE_FORCE',
      severity: 'HIGH',
      description: `Repeated remote authentication attempt blocked on port ${destPort} (SSH/RDP)`,
    };
  }

  if (isPortScan) {
    return {
      category: 'PORT_SCAN',
      severity: 'MEDIUM',
      description: `Single TCP SYN probe targeting port ${destPort}`,
    };
  }

  if (action === 'BLOCK' || action === 'DROP' || action === 'REJECT') {
    return {
      category: 'EXPLOIT_PROBE',
      severity: 'MEDIUM',
      description: `Inbound traffic denied by perimeter policy on port ${destPort}`,
    };
  }

  return {
    category: 'BENIGN',
    severity: 'INFO',
    description: 'Normal authorized network transit',
  };
}

export function parseAwsVpcFlowLog(line: string): FirewallLog | null {
  // Format: <version> <account-id> <interface-id> <srcaddr> <dstaddr> <srcport> <dstport> <protocol> <packets> <bytes> <start> <end> <action> <log-status>
  // e.g. 2 123456789010 eni-0123456789abcdef0 198.51.100.23 10.0.1.45 44123 443 6 10 5200 1620000000 1620000060 ACCEPT OK
  const parts = line.trim().split(/\s+/);
  if (parts.length < 14) return null;

  const interfaceId = parts[2];
  const sourceIp = parts[3];
  const destinationIp = parts[4];
  const sourcePort = parseInt(parts[5], 10) || 0;
  const destinationPort = parseInt(parts[6], 10) || 0;
  const protocol = detectProtocolNumber(parts[7]);
  const packets = parseInt(parts[8], 10) || 1;
  const bytes = parseInt(parts[9], 10) || 64;
  const startEpoch = parseInt(parts[10], 10) ? parseInt(parts[10], 10) * 1000 : Date.now();
  const rawAction = parts[12].toUpperCase();
  const action: FirewallAction = rawAction === 'ACCEPT' ? 'ALLOW' : 'DROP';

  const geo = lookupIpGeo(sourceIp);
  const threat = evaluateThreat(action, destinationPort, protocol, ['SYN'], bytes);

  return {
    id: generateLogId(),
    timestamp: new Date(startEpoch).toISOString(),
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    protocol,
    action,
    severity: threat.severity,
    ruleName: action === 'ALLOW' ? 'AWS-VPC-ALLOW-SG' : 'AWS-VPC-NACL-DENY',
    firewallType: 'AWS_VPC',
    interface: interfaceId,
    bytes,
    packets,
    tcpFlags: ['SYN'],
    sourceCountry: geo.countryCode,
    sourceCountryName: geo.countryName,
    sourceCity: geo.city,
    sourceAsn: geo.asn,
    threatCategory: threat.category,
    threatDescription: threat.description,
    rawLog: line,
  };
}

export function parseCiscoAsaLog(line: string): FirewallLog | null {
  // e.g. %ASA-4-106023: Deny tcp src outside:198.51.100.14/51234 dst inside:192.168.1.10/3389 by access-group "OUTSIDE-IN"
  const regex = /%(?:ASA|FTD)-\d-(\d+):\s+(Deny|Built|Teardown|Permit)\s+(\w+)\s+src\s+([^:]+):([^\/]+)\/(\d+)\s+dst\s+([^:]+):([^\/]+)\/(\d+)(?:\s+by\s+access-group\s+"([^"]+)")?/i;
  const match = line.match(regex);

  if (!match) return null;

  const rawAction = match[2].toUpperCase();
  const action: FirewallAction = rawAction.includes('DENY') ? 'DROP' : 'ALLOW';
  const protoStr = match[3].toUpperCase();
  const protocol: NetworkProtocol = protoStr.includes('TCP') ? 'TCP' : protoStr.includes('UDP') ? 'UDP' : protoStr.includes('ICMP') ? 'ICMP' : 'OTHER';
  const iface = match[4];
  const sourceIp = match[5];
  const sourcePort = parseInt(match[6], 10) || 0;
  const destinationIp = match[8];
  const destinationPort = parseInt(match[9], 10) || 0;
  const ruleName = match[10] || 'CISCO-DEFAULT-ACL';

  const geo = lookupIpGeo(sourceIp);
  const threat = evaluateThreat(action, destinationPort, protocol, ['SYN'], 128);

  return {
    id: generateLogId(),
    timestamp: new Date().toISOString(),
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    protocol,
    action,
    severity: threat.severity,
    ruleName,
    firewallType: 'CISCO_ASA',
    interface: iface,
    bytes: 128,
    packets: 1,
    tcpFlags: ['SYN'],
    sourceCountry: geo.countryCode,
    sourceCountryName: geo.countryName,
    sourceCity: geo.city,
    sourceAsn: geo.asn,
    threatCategory: threat.category,
    threatDescription: threat.description,
    rawLog: line,
  };
}

export function parseIptablesLog(line: string): FirewallLog | null {
  // e.g. Aug 16 22:51:00 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.99 DST=10.0.0.15 LEN=48 PROTO=TCP SPT=49822 DPT=22 SYN
  if (!line.includes('SRC=') || !line.includes('DST=')) return null;

  const getParam = (key: string) => {
    const m = line.match(new RegExp(`${key}=([^\\s]+)`));
    return m ? m[1] : '';
  };

  const sourceIp = getParam('SRC');
  const destinationIp = getParam('DST');
  const sourcePort = parseInt(getParam('SPT'), 10) || 0;
  const destinationPort = parseInt(getParam('DPT'), 10) || 0;
  const protoStr = getParam('PROTO');
  const protocol = detectProtocolNumber(protoStr);
  const bytes = parseInt(getParam('LEN'), 10) || 64;
  const iface = getParam('IN') || 'eth0';

  const isBlock = line.toUpperCase().includes('BLOCK') || line.toUpperCase().includes('DENY') || line.toUpperCase().includes('DROP');
  const action: FirewallAction = isBlock ? 'DROP' : 'ALLOW';
  const flags = line.includes('SYN') ? ['SYN'] : line.includes('RST') ? ['RST'] : [];

  const geo = lookupIpGeo(sourceIp);
  const threat = evaluateThreat(action, destinationPort, protocol, flags, bytes);

  return {
    id: generateLogId(),
    timestamp: new Date().toISOString(),
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    protocol,
    action,
    severity: threat.severity,
    ruleName: isBlock ? 'UFW_DEFAULT_INPUT_DROP' : 'UFW_ALLOW_IN',
    firewallType: 'IPTABLES',
    interface: iface,
    bytes,
    packets: 1,
    tcpFlags: flags,
    sourceCountry: geo.countryCode,
    sourceCountryName: geo.countryName,
    sourceCity: geo.city,
    sourceAsn: geo.asn,
    threatCategory: threat.category,
    threatDescription: threat.description,
    rawLog: line,
  };
}

export function parsePaloAltoCsvLog(line: string): FirewallLog | null {
  // Palo Alto PAN-OS CSV export
  // Format: 1,2026/08/16 22:50:00,001801000000,TRAFFIC,drop,...,srcIp,dstIp,...,srcPort,dstPort,...,proto,action
  const parts = line.split(',');
  if (parts.length < 15) return null;

  const sourceIp = parts[7] || parts[4] || '198.51.100.1';
  const destinationIp = parts[8] || parts[5] || '10.0.0.1';
  const ruleName = parts[11] || 'PA-SECURITY-POLICY';
  const sourcePort = parseInt(parts[24] || parts[9], 10) || 44123;
  const destinationPort = parseInt(parts[25] || parts[10], 10) || 443;
  const protoStr = parts[29] || 'tcp';
  const protocol = detectProtocolNumber(protoStr);
  const rawAction = (parts[30] || parts[3] || 'allow').toLowerCase();
  const action: FirewallAction = rawAction.includes('deny') || rawAction.includes('drop') || rawAction.includes('reset') ? 'DROP' : 'ALLOW';
  const bytes = parseInt(parts[31] || '512', 10) || 512;
  const packets = parseInt(parts[33] || '2', 10) || 2;

  const geo = lookupIpGeo(sourceIp);
  const threat = evaluateThreat(action, destinationPort, protocol, ['SYN'], bytes);

  return {
    id: generateLogId(),
    timestamp: new Date().toISOString(),
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    protocol,
    action,
    severity: threat.severity,
    ruleName,
    firewallType: 'PALO_ALTO',
    interface: parts[17] || 'ethernet1/1',
    bytes,
    packets,
    tcpFlags: ['SYN'],
    sourceCountry: geo.countryCode,
    sourceCountryName: geo.countryName,
    sourceCity: geo.city,
    sourceAsn: geo.asn,
    threatCategory: threat.category,
    threatDescription: threat.description,
    rawLog: line,
  };
}

export function parseFortinetLog(line: string): FirewallLog | null {
  // FortiGate key-value log
  // e.g. date=2026-08-16 time=22:50:00 devname="FGT60E" srcip=198.51.100.4 dstip=10.0.1.20 srcport=54321 dstport=3389 proto=6 action="deny" policyid=4
  if (!line.includes('srcip=') && !line.includes('src=')) return null;

  const getParam = (keys: string[]) => {
    for (const key of keys) {
      const regex = new RegExp(`(?:${key})=["']?([^"'\s,]+)["']?`);
      const m = line.match(regex);
      if (m) return m[1];
    }
    return '';
  };

  const sourceIp = getParam(['srcip', 'src']);
  const destinationIp = getParam(['dstip', 'dst']);
  const sourcePort = parseInt(getParam(['srcport', 'spt']), 10) || 0;
  const destinationPort = parseInt(getParam(['dstport', 'dpt']), 10) || 0;
  const protoStr = getParam(['proto', 'protocol']);
  const protocol = detectProtocolNumber(protoStr);
  const rawAction = getParam(['action', 'act']).toLowerCase();
  const action: FirewallAction = rawAction.includes('deny') || rawAction.includes('block') || rawAction.includes('drop') ? 'DROP' : 'ALLOW';
  const ruleName = `Policy-${getParam(['policyid', 'polid']) || 'Default'}`;
  const bytes = parseInt(getParam(['sentbyte', 'rcvdbyte', 'bytes']), 10) || 128;

  const geo = lookupIpGeo(sourceIp);
  const threat = evaluateThreat(action, destinationPort, protocol, ['SYN'], bytes);

  return {
    id: generateLogId(),
    timestamp: new Date().toISOString(),
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    protocol,
    action,
    severity: threat.severity,
    ruleName,
    firewallType: 'FORTINET',
    interface: getParam(['srcintf', 'interface']) || 'wan1',
    bytes,
    packets: 1,
    tcpFlags: ['SYN'],
    sourceCountry: geo.countryCode,
    sourceCountryName: geo.countryName,
    sourceCity: geo.city,
    sourceAsn: geo.asn,
    threatCategory: threat.category,
    threatDescription: threat.description,
    rawLog: line,
  };
}

export function parseJsonLog(objOrString: any): FirewallLog | null {
  try {
    const data = typeof objOrString === 'string' ? JSON.parse(objOrString) : objOrString;
    const sourceIp = data.sourceIp || data.src_ip || data.ClientIP || data.src || data.source_ip || '198.51.100.1';
    const destinationIp = data.destinationIp || data.dst_ip || data.dst || data.dest_ip || '10.0.0.1';
    const sourcePort = parseInt(data.sourcePort || data.src_port || data.spt || data.source_port, 10) || 0;
    const destinationPort = parseInt(data.destinationPort || data.dst_port || data.dpt || data.dest_port || data.Port || 443, 10) || 443;
    const protocol = detectProtocolNumber(data.protocol || data.proto || 'TCP');
    const rawAction = String(data.action || data.Action || data.verdict || 'ALLOW').toUpperCase();
    const action: FirewallAction = rawAction.includes('DENY') || rawAction.includes('BLOCK') || rawAction.includes('DROP') ? 'DROP' : 'ALLOW';
    const bytes = parseInt(data.bytes || data.size || data.byte_count, 10) || 512;
    const packets = parseInt(data.packets || data.packet_count, 10) || 1;
    const ruleName = data.ruleName || data.rule || data.RuleId || data.policy || 'CUSTOM_JSON_POLICY';

    const geo = lookupIpGeo(sourceIp);
    const threat = evaluateThreat(action, destinationPort, protocol, ['SYN'], bytes);

    return {
      id: generateLogId(),
      timestamp: data.timestamp || data.Datetime || new Date().toISOString(),
      sourceIp,
      sourcePort,
      destinationIp,
      destinationPort,
      protocol,
      action,
      severity: threat.severity,
      ruleName,
      firewallType: 'CUSTOM_JSON',
      interface: data.interface || 'eth0',
      bytes,
      packets,
      tcpFlags: data.tcpFlags || ['SYN'],
      sourceCountry: geo.countryCode,
      sourceCountryName: geo.countryName,
      sourceCity: geo.city,
      sourceAsn: geo.asn,
      threatCategory: threat.category,
      threatDescription: threat.description,
      rawLog: typeof objOrString === 'string' ? objOrString : JSON.stringify(data),
    };
  } catch (e) {
    return null;
  }
}

/**
 * Universal auto-detecting parser that checks the format of any log line
 */
export function parseFirewallLogLine(line: string): FirewallLog | null {
  if (!line || !line.trim()) return null;
  const trimmed = line.trim();

  // Try JSON first
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    const res = parseJsonLog(trimmed);
    if (res) return res;
  }

  // Try Cisco ASA
  if (trimmed.includes('%ASA-') || trimmed.includes('%FTD-')) {
    const res = parseCiscoAsaLog(trimmed);
    if (res) return res;
  }

  // Try iptables / UFW
  if (trimmed.includes('SRC=') && trimmed.includes('DST=')) {
    const res = parseIptablesLog(trimmed);
    if (res) return res;
  }

  // Try Fortinet CEF / Key-Value
  if (trimmed.includes('srcip=') || trimmed.includes('devname="FGT') || trimmed.includes('CEF:0|Fortinet')) {
    const res = parseFortinetLog(trimmed);
    if (res) return res;
  }

  // Try AWS VPC Flow Logs
  const awsRes = parseAwsVpcFlowLog(trimmed);
  if (awsRes) return awsRes;

  // Try Palo Alto CSV
  if (trimmed.includes(',') && trimmed.split(',').length >= 10) {
    const paRes = parsePaloAltoCsvLog(trimmed);
    if (paRes) return paRes;
  }

  // Fallback: Generic line extraction with regex
  const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const ips = trimmed.match(ipRegex);
  if (ips && ips.length >= 2) {
    const sourceIp = ips[0];
    const destinationIp = ips[1];
    const isBlock = trimmed.toLowerCase().includes('drop') || trimmed.toLowerCase().includes('block') || trimmed.toLowerCase().includes('deny');
    const action: FirewallAction = isBlock ? 'DROP' : 'ALLOW';
    const geo = lookupIpGeo(sourceIp);
    const threat = evaluateThreat(action, 443, 'TCP', ['SYN'], 256);

    return {
      id: generateLogId(),
      timestamp: new Date().toISOString(),
      sourceIp,
      sourcePort: 51234,
      destinationIp,
      destinationPort: 443,
      protocol: 'TCP',
      action,
      severity: threat.severity,
      ruleName: 'GENERIC_SYSLOG_FALLBACK',
      firewallType: 'SYSLOG',
      interface: 'eth0',
      bytes: 256,
      packets: 1,
      tcpFlags: ['SYN'],
      sourceCountry: geo.countryCode,
      sourceCountryName: geo.countryName,
      sourceCity: geo.city,
      sourceAsn: geo.asn,
      threatCategory: threat.category,
      threatDescription: threat.description,
      rawLog: line,
    };
  }

  return null;
}

export function parseBatchLogs(content: string): FirewallLog[] {
  const lines = content.split('\n');
  const results: FirewallLog[] = [];

  // Check if entire content is a single JSON array
  if (content.trim().startsWith('[') && content.trim().endsWith(']')) {
    try {
      const arr = JSON.parse(content);
      if (Array.isArray(arr)) {
        for (const item of arr) {
          const parsed = parseJsonLog(item);
          if (parsed) results.push(parsed);
        }
        return results;
      }
    } catch (e) {
      // Continue to line-by-line
    }
  }

  for (const line of lines) {
    if (!line.trim()) continue;
    const parsed = parseFirewallLogLine(line);
    if (parsed) results.push(parsed);
  }

  return results;
}
