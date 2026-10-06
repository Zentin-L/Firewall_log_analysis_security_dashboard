import { FirewallAction, FirewallLog, LogSeverity, NetworkProtocol, SecurityAlert, ThreatCategory } from '../types';
import { evaluateThreat, generateLogId } from './logParsers';
import { lookupIpGeo } from './geoData';

const ATTACKER_IPS = [
  '198.51.100.42',
  '203.0.113.195',
  '185.220.101.5',
  '45.155.205.233',
  '194.26.29.112',
  '103.145.13.88',
  '91.240.118.172',
  '193.142.146.39',
  '185.190.140.21',
  '89.248.165.71',
  '185.246.128.99',
  '167.99.145.22',
  '159.65.210.4',
  '178.62.204.81',
];

const INTERNAL_IPS = [
  '10.0.1.15',
  '10.0.1.20',
  '10.0.2.45',
  '10.0.3.100',
  '172.16.10.5',
  '172.16.20.18',
  '192.168.1.10',
  '192.168.1.50',
];

const TARGET_PORTS = [
  { port: 443, proto: 'TCP' as NetworkProtocol, service: 'HTTPS' },
  { port: 80, proto: 'TCP' as NetworkProtocol, service: 'HTTP' },
  { port: 22, proto: 'TCP' as NetworkProtocol, service: 'SSH' },
  { port: 3389, proto: 'TCP' as NetworkProtocol, service: 'RDP' },
  { port: 445, proto: 'TCP' as NetworkProtocol, service: 'SMB' },
  { port: 53, proto: 'UDP' as NetworkProtocol, service: 'DNS' },
  { port: 1433, proto: 'TCP' as NetworkProtocol, service: 'MSSQL' },
  { port: 3306, proto: 'TCP' as NetworkProtocol, service: 'MySQL' },
  { port: 8080, proto: 'TCP' as NetworkProtocol, service: 'HTTP-Alt' },
  { port: 23, proto: 'TCP' as NetworkProtocol, service: 'Telnet' },
  { port: 6379, proto: 'TCP' as NetworkProtocol, service: 'Redis' },
  { port: 5432, proto: 'TCP' as NetworkProtocol, service: 'Postgres' },
];

export function generateSingleRandomLog(isThreat = false, baseTime = Date.now()): FirewallLog {
  const now = new Date(baseTime).toISOString();
  const target = TARGET_PORTS[Math.floor(Math.random() * TARGET_PORTS.length)];
  const destIp = INTERNAL_IPS[Math.floor(Math.random() * INTERNAL_IPS.length)];
  
  let sourceIp: string;
  let action: FirewallAction;
  let threatCategory: ThreatCategory;
  let severity: LogSeverity;
  let ruleName: string;
  let bytes = Math.floor(Math.random() * 2048) + 64;
  let packets = Math.floor(Math.random() * 5) + 1;
  let tcpFlags = ['SYN'];

  if (isThreat || Math.random() < 0.35) {
    sourceIp = ATTACKER_IPS[Math.floor(Math.random() * ATTACKER_IPS.length)];
    action = Math.random() < 0.85 ? 'DROP' : 'BLOCK';
    
    // Choose realistic threat pattern
    const rand = Math.random();
    if (target.port === 22 || target.port === 3389) {
      threatCategory = 'BRUTE_FORCE';
      severity = 'HIGH';
      ruleName = 'DENY_UNAUTHORIZED_MGMT_ACCESS';
    } else if (target.port === 445 || target.port === 1433 || target.port === 3306 || target.port === 6379) {
      threatCategory = 'EXPLOIT_PROBE';
      severity = 'HIGH';
      ruleName = 'DENY_DATABASE_EXPOSURE_INBOUND';
    } else if (rand < 0.3) {
      threatCategory = 'PORT_SCAN';
      severity = 'MEDIUM';
      ruleName = 'DROP_RECON_PROBE';
    } else if (rand < 0.45) {
      threatCategory = 'DDOS_FLOOD';
      severity = 'CRITICAL';
      bytes = Math.floor(Math.random() * 45000) + 10000;
      packets = Math.floor(Math.random() * 120) + 20;
      tcpFlags = ['SYN_FLOOD'];
      ruleName = 'DDOS_RATE_LIMIT_DROP';
    } else {
      threatCategory = 'UNAUTHORIZED_ACCESS';
      severity = 'MEDIUM';
      ruleName = 'DEFAULT_PERIMETER_DROP';
    }
  } else {
    // Normal traffic
    sourceIp = Math.random() < 0.4 
      ? INTERNAL_IPS[Math.floor(Math.random() * INTERNAL_IPS.length)]
      : `142.250.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`; // benign public
    action = 'ALLOW';
    threatCategory = 'BENIGN';
    severity = 'INFO';
    ruleName = target.port === 443 ? 'ALLOW_HTTPS_INGRESS' : target.port === 80 ? 'ALLOW_HTTP_REDIRECT' : 'ALLOW_ESTABLISHED';
    bytes = Math.floor(Math.random() * 15000) + 500;
    packets = Math.floor(Math.random() * 18) + 2;
    tcpFlags = ['SYN', 'ACK', 'PSH'];
  }

  const geo = lookupIpGeo(sourceIp);
  const threatEval = evaluateThreat(action, target.port, target.proto, tcpFlags, bytes);

  const firewallTypes = ['AWS_VPC', 'PALO_ALTO', 'CISCO_ASA', 'IPTABLES', 'FORTINET'] as const;
  const fwType = firewallTypes[Math.floor(Math.random() * firewallTypes.length)];

  return {
    id: generateLogId(),
    timestamp: now,
    sourceIp,
    sourcePort: Math.floor(Math.random() * 40000) + 10240,
    destinationIp: destIp,
    destinationPort: target.port,
    protocol: target.proto,
    action,
    severity: threatCategory === 'BENIGN' ? 'INFO' : threatEval.severity,
    ruleName,
    firewallType: fwType,
    interface: Math.random() < 0.5 ? 'eth0' : 'wan1',
    bytes,
    packets,
    tcpFlags,
    sourceCountry: geo.countryCode,
    sourceCountryName: geo.countryName,
    sourceCity: geo.city,
    sourceAsn: geo.asn,
    threatCategory,
    threatDescription: threatEval.description,
    rawLog: `${now} [${fwType}] action=${action} proto=${target.proto} src=${sourceIp} dst=${destIp}:${target.port} rule=${ruleName} bytes=${bytes}`,
  };
}

export function generateInitialDataset(count = 120): FirewallLog[] {
  const logs: FirewallLog[] = [];
  const now = Date.now();
  const intervalMs = (60 * 60 * 1000) / count; // span past 1 hour

  for (let i = count; i >= 0; i--) {
    const timestamp = now - i * intervalMs + (Math.random() * 1000 - 500);
    const isThreat = Math.random() < 0.42; // ~42% threats/drops
    logs.push(generateSingleRandomLog(isThreat, timestamp));
  }

  return logs;
}

export const PRESET_DATASETS: Record<string, { name: string; description: string; logs: FirewallLog[] }> = {
  active_threats: {
    name: 'Perimeter Breach & Active Threat Scenario',
    description: 'High-intensity security telemetry showing SSH brute force, SMB probes, and multi-port recon.',
    logs: generateInitialDataset(150),
  },
  ddos_attack: {
    name: 'Volumetric SYN Flood & DDoS Burst',
    description: 'Surge in dropped SYN packets targeting HTTPS & Proxy infrastructure from distributed IP clusters.',
    logs: Array.from({ length: 180 }).map((_, i) => {
      const now = Date.now() - (180 - i) * 15000;
      const isBurst = i > 60 && i < 150;
      return generateSingleRandomLog(isBurst ? true : Math.random() < 0.2, now);
    }),
  },
  cloud_transit: {
    name: 'Multi-Cloud VPC Transit Traffic',
    description: 'Standard enterprise traffic stream across AWS VPC Flow, Cloudflare WAF, and pfSense nodes.',
    logs: Array.from({ length: 100 }).map((_, i) => {
      const now = Date.now() - (100 - i) * 30000;
      return generateSingleRandomLog(Math.random() < 0.18, now);
    }),
  },
  database_probes: {
    name: 'Database & Zero-Day Port Scans',
    description: 'Targeted unauthorized connection attempts probing Redis (6379), MS-SQL (1433), and Postgres (5432).',
    logs: Array.from({ length: 120 }).map((_, i) => {
      const now = Date.now() - (120 - i) * 20000;
      const log = generateSingleRandomLog(true, now);
      log.destinationPort = [1433, 3306, 5432, 6379, 27017][i % 5];
      log.ruleName = 'DENY_DATABASE_EXPOSURE';
      log.threatCategory = 'EXPLOIT_PROBE';
      log.severity = 'HIGH';
      return log;
    }),
  },
};

/**
 * Intelligent correlation engine to aggregate logs into high-level Security Incidents
 */
export function detectSecurityAlerts(logs: FirewallLog[]): SecurityAlert[] {
  const alerts: SecurityAlert[] = [];
  const ipGroup: Record<string, FirewallLog[]> = {};

  for (const log of logs) {
    if (!ipGroup[log.sourceIp]) {
      ipGroup[log.sourceIp] = [];
    }
    ipGroup[log.sourceIp].push(log);
  }

  for (const [ip, ipLogs] of Object.entries(ipGroup)) {
    const blockedLogs = ipLogs.filter((l) => l.action !== 'ALLOW');
    if (blockedLogs.length === 0) continue;

    const uniquePorts = Array.from(new Set(blockedLogs.map((l) => l.destinationPort)));
    const hasSshOrRdp = uniquePorts.includes(22) || uniquePorts.includes(3389) || uniquePorts.includes(23);
    const hasDbPorts = uniquePorts.some((p) => [1433, 3306, 5432, 6379, 27017, 445].includes(p));
    const totalBytes = blockedLogs.reduce((acc, l) => acc + l.bytes, 0);

    // 1. Port Scan Anomaly
    if (uniquePorts.length >= 4) {
      alerts.push({
        id: `alert-scan-${ip.replace(/\./g, '-')}`,
        title: `Host Reconnaissance & Multi-Port Sweep (${uniquePorts.length} Ports)`,
        category: 'PORT_SCAN',
        severity: uniquePorts.length >= 6 ? 'HIGH' : 'MEDIUM',
        sourceIp: ip,
        targetPorts: uniquePorts,
        eventCount: blockedLogs.length,
        firstSeen: blockedLogs[0].timestamp,
        lastSeen: blockedLogs[blockedLogs.length - 1].timestamp,
        mitreTechnique: 'T1046 - Network Service Discovery',
        description: `Source IP scanned ${uniquePorts.length} distinct target ports (${uniquePorts.slice(0, 5).join(', ')}...) in rapid succession. Blocked by firewall rules.`,
        recommendedAction: `Apply perimeter Drop rule on IP ${ip} across all ingress interfaces.`,
        status: 'ACTIVE',
      });
    }

    // 2. Brute Force Anomaly
    if (hasSshOrRdp && blockedLogs.length >= 3) {
      alerts.push({
        id: `alert-brute-${ip.replace(/\./g, '-')}`,
        title: `Persistent Remote Auth Brute-Force (SSH/RDP)`,
        category: 'BRUTE_FORCE',
        severity: 'HIGH',
        sourceIp: ip,
        targetPorts: uniquePorts.filter((p) => p === 22 || p === 3389 || p === 23),
        eventCount: blockedLogs.length,
        firstSeen: blockedLogs[0].timestamp,
        lastSeen: blockedLogs[blockedLogs.length - 1].timestamp,
        mitreTechnique: 'T1110 - Brute Force Authentication',
        description: `Repeated connection attempts to management services (Port 22/3389) blocked from unverified ASN.`,
        recommendedAction: `Add ${ip}/32 to permanent ACL blocklist and enforce Bastion / VPN requirement.`,
        status: 'ACTIVE',
      });
    }

    // 3. Database / Critical Asset Exploit Probe
    if (hasDbPorts && blockedLogs.length >= 2) {
      alerts.push({
        id: `alert-db-${ip.replace(/\./g, '-')}`,
        title: `Direct Database & SMB Infrastructure Exploitation Attempt`,
        category: 'EXPLOIT_PROBE',
        severity: 'CRITICAL',
        sourceIp: ip,
        targetPorts: uniquePorts.filter((p) => [1433, 3306, 5432, 6379, 27017, 445].includes(p)),
        eventCount: blockedLogs.length,
        firstSeen: blockedLogs[0].timestamp,
        lastSeen: blockedLogs[blockedLogs.length - 1].timestamp,
        mitreTechnique: 'T1190 - Exploit Public-Facing Application',
        description: `Unauthorized ingress requests directly targeting database/storage services (Port ${uniquePorts.filter(p => [1433, 3306, 5432, 6379, 445].includes(p)).join(', ')}).`,
        recommendedAction: `Verify zero database ports are exposed to 0.0.0.0/0 on cloud security groups.`,
        status: 'ACTIVE',
      });
    }

    // 4. Volumetric Flood Anomaly
    if (totalBytes > 60000 || blockedLogs.length >= 15) {
      alerts.push({
        id: `alert-flood-${ip.replace(/\./g, '-')}`,
        title: `High-Rate Packet Flood / Potential DoS`,
        category: 'DDOS_FLOOD',
        severity: 'CRITICAL',
        sourceIp: ip,
        targetPorts: uniquePorts,
        eventCount: blockedLogs.length,
        firstSeen: blockedLogs[0].timestamp,
        lastSeen: blockedLogs[blockedLogs.length - 1].timestamp,
        mitreTechnique: 'T1498 - Network Denial of Service',
        description: `High packet rate from ${ip} causing significant perimeter drop volume (${(totalBytes / 1024).toFixed(1)} KB denied).`,
        recommendedAction: `Trigger edge upstream BGP blackholing or Cloudflare rate limiting.`,
        status: 'ACTIVE',
      });
    }
  }

  // Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
  const rank: Record<LogSeverity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  return alerts.sort((a, b) => rank[b.severity] - rank[a.severity]);
}
