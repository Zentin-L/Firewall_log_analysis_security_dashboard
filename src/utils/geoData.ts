// Geo helper and country lookup tables for firewall logs

export interface CountryInfo {
  code: string;
  name: string;
  flag: string;
  lat: number;
  lng: number;
}

export const COUNTRY_MAP: Record<string, CountryInfo> = {
  US: { code: 'US', name: 'United States', flag: '🇺🇸', lat: 37.0902, lng: -95.7129 },
  CN: { code: 'CN', name: 'China', flag: '🇨🇳', lat: 35.8617, lng: 104.1954 },
  RU: { code: 'RU', name: 'Russia', flag: '🇷🇺', lat: 61.524, lng: 105.3188 },
  DE: { code: 'DE', name: 'Germany', flag: '🇩🇪', lat: 51.1657, lng: 10.4515 },
  NL: { code: 'NL', name: 'Netherlands', flag: '🇳🇱', lat: 52.1326, lng: 5.2913 },
  GB: { code: 'GB', name: 'United Kingdom', flag: '🇬🇧', lat: 55.3781, lng: -3.436 },
  FR: { code: 'FR', name: 'France', flag: '🇫🇷', lat: 46.2276, lng: 2.2137 },
  BR: { code: 'BR', name: 'Brazil', flag: '🇧🇷', lat: -14.235, lng: -51.9253 },
  IN: { code: 'IN', name: 'India', flag: '🇮🇳', lat: 20.5937, lng: 78.9629 },
  JP: { code: 'JP', name: 'Japan', flag: '🇯🇵', lat: 36.2048, lng: 138.2529 },
  KR: { code: 'KR', name: 'South Korea', flag: '🇰🇷', lat: 35.9078, lng: 127.7669 },
  IR: { code: 'IR', name: 'Iran', flag: '🇮🇷', lat: 32.4279, lng: 53.688 },
  UA: { code: 'UA', name: 'Ukraine', flag: '🇺🇦', lat: 48.3794, lng: 31.1656 },
  VN: { code: 'VN', name: 'Vietnam', flag: '🇻🇳', lat: 14.0583, lng: 108.2772 },
  ID: { code: 'ID', name: 'Indonesia', flag: '🇮🇩', lat: -0.7893, lng: 113.9213 },
  RO: { code: 'RO', name: 'Romania', flag: '🇷🇴', lat: 45.9432, lng: 24.9668 },
  SG: { code: 'SG', name: 'Singapore', flag: '🇸🇬', lat: 1.3521, lng: 103.8198 },
  CA: { code: 'CA', name: 'Canada', flag: '🇨🇦', lat: 56.1304, lng: -106.3468 },
  AU: { code: 'AU', name: 'Australia', flag: '🇦🇺', lat: -25.2744, lng: 133.7751 },
  INTERNAL: { code: 'LOCAL', name: 'Internal Network / RFC1918', flag: '🛡️', lat: 0, lng: 0 },
};

export function isPrivateIp(ip: string): boolean {
  if (!ip) return false;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip === '127.0.0.1' || ip === 'localhost') return true;
  if (ip.startsWith('172.')) {
    const parts = ip.split('.');
    const second = parseInt(parts[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

export function lookupIpGeo(ip: string): {
  countryCode: string;
  countryName: string;
  city: string;
  asn: string;
  flag: string;
} {
  if (!ip) {
    return { countryCode: 'US', countryName: 'United States', city: 'Ashburn', asn: 'AS16509 Amazon', flag: '🇺🇸' };
  }

  if (isPrivateIp(ip)) {
    return {
      countryCode: 'LOCAL',
      countryName: 'Internal Network',
      city: 'LAN Subnet',
      asn: 'AS-PRIVATE Enterprise LAN',
      flag: '🛡️',
    };
  }

  // Deterministic lookup based on IP hash
  const hash = ip.split('.').reduce((acc, part) => (acc * 31 + parseInt(part || '0', 10)) % 100000, 0);

  const countries = [
    { code: 'US', name: 'United States', city: 'Ashburn, VA', asn: 'AS14061 DigitalOcean', flag: '🇺🇸' },
    { code: 'CN', name: 'China', city: 'Hangzhou', asn: 'AS4134 Chinanet Backbone', flag: '🇨🇳' },
    { code: 'RU', name: 'Russia', city: 'Moscow', asn: 'AS12389 Rostelecom', flag: '🇷🇺' },
    { code: 'DE', name: 'Germany', city: 'Frankfurt', asn: 'AS24940 Hetzner Online', flag: '🇩🇪' },
    { code: 'NL', name: 'Netherlands', city: 'Amsterdam', asn: 'AS60781 LeaseWeb', flag: '🇳🇱' },
    { code: 'GB', name: 'United Kingdom', city: 'London', asn: 'AS5413 British Telecom', flag: '🇬🇧' },
    { code: 'BR', name: 'Brazil', city: 'São Paulo', asn: 'AS28573 Claro S.A.', flag: '🇧🇷' },
    { code: 'IN', name: 'India', city: 'Bangalore', asn: 'AS55836 Reliance Jio', flag: '🇮🇳' },
    { code: 'JP', name: 'Japan', city: 'Tokyo', asn: 'AS2514 NTT Communications', flag: '🇯🇵' },
    { code: 'KR', name: 'South Korea', city: 'Seoul', asn: 'AS4766 Korea Telecom', flag: '🇰🇷' },
    { code: 'VN', name: 'Vietnam', city: 'Hanoi', asn: 'AS7552 Viettel', flag: '🇻🇳' },
    { code: 'RO', name: 'Romania', city: 'Bucharest', asn: 'AS8708 RCS & RDS', flag: '🇷🇴' },
    { code: 'IR', name: 'Iran', city: 'Tehran', asn: 'AS58224 TCI', flag: '🇮🇷' },
    { code: 'SG', name: 'Singapore', city: 'Singapore', asn: 'AS4657 StarHub', flag: '🇸🇬' },
  ];

  const selected = countries[hash % countries.length];
  return {
    countryCode: selected.code,
    countryName: selected.name,
    city: selected.city,
    asn: selected.asn,
    flag: selected.flag,
  };
}

export const PORT_SERVICE_NAMES: Record<number, string> = {
  20: 'FTP Data',
  21: 'FTP Control',
  22: 'SSH Remote Login',
  23: 'Telnet (Unencrypted)',
  25: 'SMTP Mail Server',
  53: 'DNS Resolution',
  80: 'HTTP Web Server',
  110: 'POP3 Mail',
  123: 'NTP Time Sync',
  143: 'IMAP Mail',
  161: 'SNMP Network Mgmt',
  389: 'LDAP Directory',
  443: 'HTTPS TLS Web',
  445: 'SMB / Windows Share',
  1433: 'MS-SQL Database',
  1521: 'Oracle DB',
  3306: 'MySQL Database',
  3389: 'RDP Remote Desktop',
  5432: 'PostgreSQL Database',
  5900: 'VNC Remote Display',
  6379: 'Redis Cache',
  8080: 'HTTP Alternate / Proxy',
  8443: 'HTTPS Alternate',
  9200: 'Elasticsearch',
  27017: 'MongoDB Database',
};

export function getPortServiceName(port: number): string {
  return PORT_SERVICE_NAMES[port] || `Port ${port}`;
}
