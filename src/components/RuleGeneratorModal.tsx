import React, { useState } from 'react';
import { 
  X, 
  ShieldBan, 
  Terminal, 
  Copy, 
  Check, 
  Layers, 
  CheckCircle2,
  FileCode
} from 'lucide-react';

interface RuleGeneratorModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetIp: string;
}

export const RuleGeneratorModal: React.FC<RuleGeneratorModalProps> = ({
  isOpen,
  onClose,
  targetIp,
}) => {
  const [selectedFormat, setSelectedFormat] = useState<'iptables' | 'ufw' | 'cisco' | 'aws' | 'cloudflare' | 'pfsense'>('iptables');
  const [copied, setCopied] = useState(false);

  if (!isOpen || !targetIp) return null;

  const getRuleCode = () => {
    switch (selectedFormat) {
      case 'iptables':
        return `# Linux iptables drop rule
iptables -I INPUT -s ${targetIp} -j DROP
iptables -I FORWARD -s ${targetIp} -j DROP
# Save persistent
iptables-save > /etc/iptables/rules.v4`;

      case 'ufw':
        return `# Ubuntu UFW Firewall Rule
sudo ufw insert 1 deny from ${targetIp} to any comment 'NetSentinel Threat Block'
sudo ufw reload`;

      case 'cisco':
        return `! Cisco ASA / Firepower Perimeter ACL
access-list OUTSIDE_IN line 1 extended deny ip host ${targetIp} any log interval 300
access-group OUTSIDE_IN in interface outside
write memory`;

      case 'aws':
        return `{
  "Type": "AWS::WAFv2::IPSet",
  "Properties": {
    "Name": "NetSentinel-Threat-Blocklist",
    "Scope": "REGIONAL",
    "IPAddressVersion": "IPV4",
    "Addresses": [
      "${targetIp}/32"
    ],
    "Description": "Blocked by NetSentinel Firewall Analytics"
  }
}`;

      case 'cloudflare':
        return `(ip.src eq ${targetIp})
Action: Block
Description: NetSentinel Threat IP Block`;

      case 'pfsense':
        return `<rule>
  <id>10000002</id>
  <type>block</type>
  <interface>wan</interface>
  <ipprotocol>inet</ipprotocol>
  <source>
    <address>${targetIp}</address>
  </source>
  <destination>
    <any></any>
  </destination>
  <descr><![CDATA[NetSentinel Automated Block - ${targetIp}]]></descr>
</rule>`;
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(getRuleCode());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div 
        className="w-full max-w-2xl bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/70">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-rose-950 text-rose-400 border border-rose-800/60">
              <ShieldBan className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">
                Generate Firewall Mitigation Rule
              </h3>
              <p className="text-xs text-slate-400">
                Target IP: <span className="text-rose-400 font-mono font-bold">{targetIp}</span>
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Format Selector Tabs */}
        <div className="flex border-b border-slate-800 bg-slate-900/40 px-5 overflow-x-auto">
          {[
            { id: 'iptables', label: 'iptables' },
            { id: 'ufw', label: 'UFW' },
            { id: 'cisco', label: 'Cisco ASA' },
            { id: 'aws', label: 'AWS WAF' },
            { id: 'cloudflare', label: 'Cloudflare' },
            { id: 'pfsense', label: 'pfSense' },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setSelectedFormat(item.id as any)}
              className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all whitespace-nowrap ${
                selectedFormat === item.id
                  ? 'border-rose-400 text-rose-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Copy-Paste Rule Definition:</span>
            </span>

            <button
              onClick={handleCopy}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied to Clipboard' : 'Copy Rule Code'}</span>
            </button>
          </div>

          <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto leading-relaxed">
            {getRuleCode()}
          </pre>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Apply this rule at your perimeter to immediately null-route and drop incoming transit from {targetIp}.</span>
          </div>
        </div>
      </div>
    </div>
  );
};
