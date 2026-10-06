import React, { useState, useRef } from 'react';
import { 
  X, 
  UploadCloud, 
  FileText, 
  CheckCircle2, 
  AlertCircle, 
  Terminal, 
  Layers, 
  Sparkles, 
  Copy, 
  Check, 
  Database,
  ArrowRight,
  RefreshCw
} from 'lucide-react';
import { parseBatchLogs } from '../utils/logParsers';
import { FirewallLog } from '../types';
import { PRESET_DATASETS } from '../utils/sampleData';

interface ConnectorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onIngestLogs: (newLogs: FirewallLog[]) => void;
  onSelectPreset: (presetKey: string) => void;
}

export const ConnectorModal: React.FC<ConnectorModalProps> = ({
  isOpen,
  onClose,
  onIngestLogs,
  onSelectPreset,
}) => {
  const [activeTab, setActiveTab] = useState<'upload' | 'paste' | 'webhook' | 'presets'>('upload');
  const [pasteContent, setPasteContent] = useState('');
  const [parsedPreview, setParsedPreview] = useState<FirewallLog[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [ingestStatus, setIngestStatus] = useState<string | null>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [isSendingWebhookTest, setIsSendingWebhookTest] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  // Handle file reading
  const handleProcessFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      if (text) {
        const parsed = parseBatchLogs(text);
        if (parsed.length > 0) {
          onIngestLogs(parsed);
          setIngestStatus(`Successfully parsed and connected ${parsed.length} firewall log events from ${file.name}`);
          setTimeout(() => {
            onClose();
          }, 1500);
        } else {
          setIngestStatus('Could not identify valid firewall log format in this file.');
        }
      }
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleProcessFile(e.dataTransfer.files[0]);
    }
  };

  const handlePasteChange = (text: string) => {
    setPasteContent(text);
    if (text.trim()) {
      const parsed = parseBatchLogs(text);
      setParsedPreview(parsed);
    } else {
      setParsedPreview([]);
    }
  };

  const handleIngestPasted = () => {
    if (parsedPreview.length > 0) {
      onIngestLogs(parsedPreview);
      setIngestStatus(`Connected ${parsedPreview.length} logs!`);
      setTimeout(() => {
        onClose();
      }, 1000);
    }
  };

  const sampleCurl = `curl -X POST https://\${APP_URL}/api/logs/ingest \\
  -H "Content-Type: text/plain" \\
  --data-binary @firewall.log`;

  const handleSendWebhookTest = async () => {
    setIsSendingWebhookTest(true);
    try {
      const testPayload = `Aug 16 23:10:00 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.5 DST=10.0.1.20 LEN=60 PROTO=TCP SPT=52411 DPT=22 SYN
2 123456789010 eni-0123456789abcdef0 45.155.205.233 10.0.1.45 44123 3389 6 10 5200 1620000000 1620000060 REJECT OK
%ASA-4-106023: Deny tcp src outside:194.26.29.112/51234 dst inside:192.168.1.10/1433 by access-group "OUTSIDE-IN"`;

      const res = await fetch('/api/logs/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: testPayload,
      });
      const data = await res.json();
      if (data.success) {
        const parsed = parseBatchLogs(testPayload);
        onIngestLogs(parsed);
        setIngestStatus(`Webhook received: ${data.message}`);
        setTimeout(() => onClose(), 1200);
      }
    } catch (err: any) {
      setIngestStatus(`Webhook error: ${err.message}`);
    } finally {
      setIsSendingWebhookTest(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div 
        className="w-full max-w-3xl bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-950 text-cyan-400 border border-cyan-800/60">
              <UploadCloud className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">
                Connect Firewall Logs & Telemetry
              </h3>
              <p className="text-xs text-slate-400">
                Ingest logs from cloud firewalls, on-prem hardware, syslog shippers, or local files
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

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 bg-slate-900/40 px-4 sm:px-5">
          <button
            onClick={() => setActiveTab('upload')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'upload'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Upload Log File</span>
          </button>
          <button
            onClick={() => setActiveTab('paste')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'paste'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Paste Raw Logs</span>
          </button>
          <button
            onClick={() => setActiveTab('webhook')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'webhook'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Syslog / Webhook API</span>
          </button>
          <button
            onClick={() => setActiveTab('presets')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'presets'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            <span>Attack Scenarios</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-5">
          {/* Status message */}
          {ingestStatus && (
            <div className="mb-4 p-3 rounded-lg bg-cyan-950/60 border border-cyan-800 text-cyan-200 text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>{ingestStatus}</span>
            </div>
          )}

          {/* TAB 1: File Upload */}
          {activeTab === 'upload' && (
            <div className="space-y-4">
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragging(true);
                }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
                  isDragging
                    ? 'border-cyan-400 bg-cyan-950/20'
                    : 'border-slate-800 hover:border-slate-700 bg-slate-900/40 hover:bg-slate-900/60'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".log,.txt,.csv,.json"
                  className="hidden"
                  onChange={(e) => {
                    if (e.target.files && e.target.files.length > 0) {
                      handleProcessFile(e.target.files[0]);
                    }
                  }}
                />
                <div className="h-12 w-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto mb-3 text-cyan-400">
                  <UploadCloud className="w-6 h-6" />
                </div>
                <h4 className="text-sm font-bold text-white mb-1">
                  Drag and drop your firewall log file here
                </h4>
                <p className="text-xs text-slate-400 mb-3">
                  Supports AWS VPC Flow, Palo Alto CSV, Cisco ASA Syslog, iptables/UFW, Cloudflare, Fortinet, and JSON.
                </p>
                <span className="inline-block px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition-colors">
                  Browse Local Files (.log, .csv, .json)
                </span>
              </div>

              {/* Supported Formats Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 text-[11px] font-mono">
                <div className="p-2 rounded bg-slate-900/70 border border-slate-800 text-slate-300">
                  <span className="text-cyan-400 font-bold block">AWS VPC Flow</span>
                  <span>v2 NACL & SG logs</span>
                </div>
                <div className="p-2 rounded bg-slate-900/70 border border-slate-800 text-slate-300">
                  <span className="text-cyan-400 font-bold block">Palo Alto PAN-OS</span>
                  <span>Traffic CSV & Syslog</span>
                </div>
                <div className="p-2 rounded bg-slate-900/70 border border-slate-800 text-slate-300">
                  <span className="text-cyan-400 font-bold block">Cisco ASA / FTD</span>
                  <span>%ASA-4-106023 events</span>
                </div>
                <div className="p-2 rounded bg-slate-900/70 border border-slate-800 text-slate-300">
                  <span className="text-cyan-400 font-bold block">iptables / UFW</span>
                  <span>Linux kernel drops</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: Paste Raw Logs */}
          {activeTab === 'paste' && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Paste raw log lines (syslog or JSON):
                </label>
                <textarea
                  rows={8}
                  placeholder={`2 123456789010 eni-abcde123 185.220.101.5 10.0.1.45 44123 22 6 10 5200 1620000000 1620000060 REJECT OK
Aug 16 22:51:00 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.99 DST=10.0.0.15 LEN=48 PROTO=TCP SPT=49822 DPT=3389 SYN
%ASA-4-106023: Deny tcp src outside:203.0.113.195/51234 dst inside:192.168.1.10/445 by access-group "OUTSIDE-IN"`}
                  value={pasteContent}
                  onChange={(e) => handlePasteChange(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed"
                />
              </div>

              {/* Parsing Feedback */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-900/80 border border-slate-800">
                <div className="text-xs">
                  <span className="text-slate-400">Parsed Valid Events: </span>
                  <span className="font-mono font-bold text-cyan-400">
                    {parsedPreview.length} logs detected
                  </span>
                </div>

                <button
                  id="btn-ingest-pasted-logs"
                  onClick={handleIngestPasted}
                  disabled={parsedPreview.length === 0}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:pointer-events-none text-white text-xs font-semibold transition-colors"
                >
                  Ingest {parsedPreview.length} Logs to Dashboard
                </button>
              </div>
            </div>
          )}

          {/* TAB 3: Syslog / Webhook Ingestion API */}
          {activeTab === 'webhook' && (
            <div className="space-y-4">
              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                    Live Webhook Ingestion Endpoint
                  </h4>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono font-bold">
                    POST /api/logs/ingest
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  You can ship raw syslog streams, JSON events, or log files straight to this dashboard using curl or any standard log shipper (Filebeat, Logstash, FluentBit).
                </p>
              </div>

              {/* Curl Example */}
              <div>
                <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                  <span>cURL Command Example:</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(sampleCurl);
                      setCopiedCurl(true);
                      setTimeout(() => setCopiedCurl(false), 2000);
                    }}
                    className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-mono text-[11px]"
                  >
                    {copiedCurl ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedCurl ? 'Copied' : 'Copy cURL'}</span>
                  </button>
                </div>
                <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto">
                  {sampleCurl}
                </pre>
              </div>

              {/* Live Webhook Test Button */}
              <div className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-800/60 flex items-center justify-between gap-3">
                <div className="text-xs text-cyan-200">
                  Test the real webhook endpoint by sending 3 simulated firewall alert packets now.
                </div>
                <button
                  id="btn-send-webhook-test"
                  onClick={handleSendWebhookTest}
                  disabled={isSendingWebhookTest}
                  className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition-colors shrink-0 flex items-center gap-1.5"
                >
                  {isSendingWebhookTest && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>Send Test Webhook</span>
                </button>
              </div>
            </div>
          )}

          {/* TAB 4: Attack Scenarios & Presets */}
          {activeTab === 'presets' && (
            <div className="space-y-3">
              <p className="text-xs text-slate-400">
                Load curated, realistic firewall telemetry datasets to test analytics and threat correlation:
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {Object.entries(PRESET_DATASETS).map(([key, item]) => (
                  <div
                    key={key}
                    onClick={() => {
                      onSelectPreset(key);
                      onClose();
                    }}
                    className="p-3.5 rounded-xl bg-slate-900/70 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-700/60 cursor-pointer transition-all group"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <h4 className="text-xs font-bold text-white group-hover:text-cyan-400 transition-colors">
                        {item.name}
                      </h4>
                      <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      {item.description}
                    </p>
                    <div className="mt-2 text-[10px] text-cyan-400 font-mono">
                      {item.logs.length} telemetry records
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
