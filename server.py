from flask import Flask, send_file, jsonify, request, render_template_string
from flask_cors import CORS
import os
import json
import xml.etree.ElementTree as ET
import uuid

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(__file__)
DASHBOARD_PATH = os.path.join(BASE_DIR, 'dashboard.html')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DATA_FILE = os.path.join(BASE_DIR, 'data.json')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DEFAULT_DATA = {
    "timeline": [
        {"time": "APR 21", "title": "ServiceV1 External Connections", "tech": "T1071", "tactics": "[TA0011]", "desc": "servicev1.exe connected to 1.178.224.2:22 (SSH) and 1.20.0.15:443", "impact": "External C2 communication detected", "severity": "critical"}
    ],
    "suspicious_ips": [
        {"ip": "1.178.224.2", "label": "SHEPHERD", "type": "PRIMARY ATTACKER", "status": "ACTIVE"},
        {"ip": "1.20.0.15", "label": "WOLF", "type": "C2", "status": "ACTIVE"},
        {"ip": "192.108.28.105", "label": "SHEPHERD", "type": "ATTACKER", "status": "BLOCKED"},
        {"ip": "1.146.108.60", "label": "RAM", "type": "ATTACKER", "status": "BLOCKED"}
    ],
    "phishing_domains": [
        {"domain": "technexus.pl", "type": "C2"},
        {"domain": "ctldl.windowsupdate.com", "type": "C2"}
    ],
    "threat_intel": [
        {"text": "LIKELY: T1114 - Email Collection", "mitre": "T1114"},
        {"text": "LIKELY: T1087 - Account Discovery", "mitre": "T1087"},
        {"text": "POSSIBLE: T1003 - OS Credential Dumping", "mitre": "T1003"}
    ],
    "recommendations": [
        {"text": "Investigate Microsoft Office suspicious activity", "mitre": "T1566", "status": "active"},
        {"text": "Monitor core routers for further SSH access", "mitre": "T1021", "status": "active"}
    ]
}

def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return DEFAULT_DATA.copy()

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

@app.route('/api/data')
def get_data():
    return jsonify(load_data())

@app.route('/api/data', methods=['POST'])
def update_data():
    data = request.json
    save_data(data)
    return jsonify({"success": True})

ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin - Operation Digital Fortitude</title>
    <link href="https://fonts.googleapis.com/css2?family=Black+Ops+One&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Rajdhani', sans-serif; background: #0a0a0a; color: #b8c4ce; min-height: 100vh; }
        .sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: 50px; background: #0f0f14; border-right: 1px solid #2a2a35; padding: 20px 0; z-index: 1000; transition: width 0.3s ease; overflow: hidden; }
        .sidebar:hover { width: 200px; }
        .sidebar-item { display: flex; align-items: center; padding: 15px 15px; color: #7a8595; text-decoration: none; border-left: 3px solid transparent; transition: all 0.3s; white-space: nowrap; }
        .sidebar-item:hover { background: #1a1a22; color: #c0c8d0; }
        .sidebar-item.active { background: #1a1a22; color: #5e9eff; border-left-color: #5e9eff; }
        .sidebar-item span { min-width: 30px; font-size: 18px; }
        .main-content { margin-left: 50px; transition: margin-left 0.3s ease; }
        .header { background: linear-gradient(180deg, #1a1a22 0%, #0f0f14 100%); padding: 15px 30px; border-bottom: 3px solid #5e9eff; }
        .header h1 { color: #5e9eff; font-family: 'Black Ops One', cursive; font-size: 20px; }
        .container { padding: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .card { background: #15151d; border: 1px solid #2a2a35; border-radius: 10px; padding: 20px; }
        .card h2 { color: #5e9eff; font-size: 16px; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #2a2a35; display: flex; justify-content: space-between; align-items: center; }
        .card h2 .count { background: #2a3a4a; padding: 2px 10px; border-radius: 10px; font-size: 12px; }
        .item { background: #0d0d12; border: 1px solid #2a2a35; border-radius: 6px; padding: 12px; margin-bottom: 10px; position: relative; }
        .item:hover { border-color: #5e9eff; }
        .item-row { display: flex; gap: 10px; margin-bottom: 8px; }
        .item-row label { min-width: 80px; color: #6a7585; font-size: 12px; padding-top: 8px; }
        .item-row input, .item-row select { flex: 1; background: #1a1a22; border: 1px solid #2a2a35; color: #c0c8d0; padding: 8px; border-radius: 4px; font-size: 13px; }
        .item-row input:focus { outline: none; border-color: #5e9eff; }
        .btn { background: #5e9eff; color: #0a0a0a; padding: 8px 16px; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; font-size: 12px; }
        .btn:hover { background: #7ab3ff; }
        .btn.add { background: #4ecdc4; }
        .btn.delete { background: #ff4444; color: white; padding: 4px 10px; }
        .btn.save { background: #5e9eff; width: 100%; padding: 12px; font-size: 14px; margin-top: 20px; }
        .empty { color: #6a7585; text-align: center; padding: 20px; font-style: italic; }
        .nav { display: flex; gap: 10px; margin-bottom: 20px; }
        .nav a { color: #5e9eff; text-decoration: none; padding: 10px 20px; background: #15151d; border-radius: 5px; }
        .nav a:hover { background: #1a2535; }
        .sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: 50px; background: #0f0f14; border-right: 1px solid #2a2a35; padding: 20px 0; z-index: 1000; transition: width 0.3s ease; overflow: hidden; }
        .sidebar:hover { width: 200px; }
        .sidebar-item { display: flex; align-items: center; padding: 15px 15px; color: #7a8595; text-decoration: none; border-left: 3px solid transparent; transition: all 0.3s; white-space: nowrap; }
        .sidebar-item:hover { background: #1a1a22; color: #c0c8d0; }
        .sidebar-item.active { background: #1a1a22; color: #5e9eff; border-left-color: #5e9eff; }
        .sidebar-item span { min-width: 30px; font-size: 18px; }
        .main-content { margin-left: 50px; transition: margin-left 0.3s ease; }
    </style>
</head>
<body>
    <div class="sidebar">
        <a href="/" class="sidebar-item"><span>📊</span>Dashboard</a>
        <a href="/network-map" class="sidebar-item"><span>🗺️</span>Network Map</a>
        <a href="/reports" class="sidebar-item"><span>📋</span>Reports</a>
        <a href="/admin" class="sidebar-item active"><span>⚙️</span>Admin</a>
    </div>
    <div class="main-content">
    <div class="header">
        <h1>Admin Console - Operation Digital Fortitude</h1>
    </div>
    <div class="container">
        <div class="card">
            <h2>🐑 Suspicious IPs <span class="count" id="ipCount">0</span></h2>
            <div id="ipList"></div>
            <button class="btn add" onclick="addIP()">➕ Add IP</button>
        </div>
        
        <div class="card">
            <h2>🎣 Phishing Domains <span class="count" id="domainCount">0</span></h2>
            <div id="domainList"></div>
            <button class="btn add" onclick="addDomain()">➕ Add Domain</button>
        </div>
        
        <div class="card">
            <h2>📋 Timeline Events <span class="count" id="timelineCount">0</span></h2>
            <div id="timelineList"></div>
            <button class="btn add" onclick="addTimeline()">➕ Add Event</button>
        </div>
        
        <div class="card">
            <h2>📋 Recommendations <span class="count" id="recCount">0</span></h2>
            <div id="recList"></div>
            <button class="btn add" onclick="addRec()">➕ Add Recommendation</button>
        </div>
    </div>
    <div class="container">
        <button class="btn save" onclick="saveAll()">💾 SAVE ALL CHANGES</button>
    </div>
    
    <script>
        let data = null;
        
        function loadData() {
            fetch('/api/data').then(r => r.json()).then(d => {
                data = d;
                renderAll();
            });
        }
        
        function renderAll() {
            renderIPs();
            renderDomains();
            renderTimeline();
            renderRecs();
        }
        
        function renderIPs() {
            const list = document.getElementById('ipList');
            const ips = data.suspicious_ips || [];
            document.getElementById('ipCount').textContent = ips.length;
            if (!ips.length) { list.innerHTML = '<div class="empty">No IPs added</div>'; return; }
            list.innerHTML = ips.map((ip, i) => renderItem(ip, 'ip', i)).join('');
        }
        
        function renderDomains() {
            const list = document.getElementById('domainList');
            const domains = data.phishing_domains || [];
            document.getElementById('domainCount').textContent = domains.length;
            if (!domains.length) { list.innerHTML = '<div class="empty">No domains added</div>'; return; }
            list.innerHTML = domains.map((d, i) => renderItem(d, 'domain', i)).join('');
        }
        
        function renderTimeline() {
            const list = document.getElementById('timelineList');
            const items = data.timeline || [];
            document.getElementById('timelineCount').textContent = items.length;
            if (!items.length) { list.innerHTML = '<div class="empty">No events added</div>'; return; }
            list.innerHTML = items.map((t, i) => renderTimelineItem(t, i)).join('');
        }
        
        function renderRecs() {
            const list = document.getElementById('recList');
            const items = data.recommendations || [];
            document.getElementById('recCount').textContent = items.length;
            if (!items.length) { list.innerHTML = '<div class="empty">No recommendations</div>'; return; }
            list.innerHTML = items.map((r, i) => renderItem(r, 'rec', i)).join('');
        }
        
        function renderItem(obj, type, idx) {
            if (type === 'ip') {
                return `<div class="item">
                    <div class="item-row"><label>IP</label><input value="${obj.ip || ''}" onchange="update('suspicious_ips',${idx},'ip',this.value)"></div>
                    <div class="item-row"><label>Label</label><input value="${obj.label || ''}" onchange="update('suspicious_ips',${idx},'label',this.value)"></div>
                    <div class="item-row"><label>Type</label><input value="${obj.type || ''}" onchange="update('suspicious_ips',${idx},'type',this.value)"></div>
                    <div class="item-row"><label>Status</label><select onchange="update('suspicious_ips',${idx},'status',this.value)"><option ${obj.status==='ACTIVE'?'selected':''}>ACTIVE</option><option ${obj.status==='BLOCKED'?'selected':''}>BLOCKED</option></select></div>
                    <button class="btn delete" onclick="deleteItem('suspicious_ips',${idx})">🗑️ Delete</button>
                </div>`;
            }
            if (type === 'domain') {
                return `<div class="item">
                    <div class="item-row"><label>Domain</label><input value="${obj.domain || ''}" onchange="update('phishing_domains',${idx},'domain',this.value)"></div>
                    <div class="item-row"><label>Type</label><input value="${obj.type || ''}" onchange="update('phishing_domains',${idx},'type',this.value)"></div>
                    <button class="btn delete" onclick="deleteItem('phishing_domains',${idx})">🗑️ Delete</button>
                </div>`;
            }
            if (type === 'rec') {
                return `<div class="item">
                    <div class="item-row"><label>Text</label><input value="${obj.text || ''}" onchange="update('recommendations',${idx},'text',this.value)"></div>
                    <div class="item-row"><label>MITRE</label><input value="${obj.mitre || ''}" onchange="update('recommendations',${idx},'mitre',this.value)"></div>
                    <div class="item-row"><label>Status</label><select onchange="update('recommendations',${idx},'status',this.value)"><option ${obj.status==='active'?'selected':''}>active</option><option ${obj.status==='completed'?'selected':''}>completed</option></select></div>
                    <button class="btn delete" onclick="deleteItem('recommendations',${idx})">🗑️ Delete</button>
                </div>`;
            }
            return '';
        }
        
        function renderTimelineItem(obj, idx) {
            const timeStr = obj.time || '';
            const dateMatch = timeStr.match(/([A-Z]+)\s*(\d+)/i);
            let isoDate = '';
            if (dateMatch) {
                const months = {JAN:0,FEB:1,MAR:2,APR:3,MAY:4,JUN:5,JUL:6,AUG:7,SEP:8,OCT:9,NOV:10,DEC:11};
                const mo = months[dateMatch[1].toUpperCase().slice(0,3)];
                if (mo !== undefined) {
                    const d = new Date(2026, mo, parseInt(dateMatch[2]));
                    isoDate = d.toISOString().split('T')[0];
                }
            }
            const timeOnly = timeStr.replace(/[A-Z]+\s*\d+\s*/i, '').trim();
            return `<div class="item">
                <div class="item-row"><label>Date</label><input type="date" id="date_${idx}" value="${isoDate}" onchange="updateTime(${idx},this.value,document.getElementById('time_${idx}').value)" style="background:#1a1a22;border:1px solid #2a2a35;color:#c0c8d0;padding:8px;border-radius:4px;"></div>
                <div class="item-row"><label>Time</label><input id="time_${idx}" value="${timeOnly}" onchange="updateTime(${idx},document.getElementById('date_${idx}').value,this.value)" placeholder="HH:MM"></div>
                <div class="item-row"><label>Title</label><input value="${obj.title || ''}" onchange="update('timeline',${idx},'title',this.value)"></div>
                <div class="item-row"><label>Tech</label><input value="${obj.tech || ''}" onchange="update('timeline',${idx},'tech',this.value)"></div>
                <div class="item-row"><label>Tactics</label><input value="${obj.tactics || ''}" onchange="update('timeline',${idx},'tactics',this.value)"></div>
                <div class="item-row"><label>Description</label><input value="${obj.desc || ''}" onchange="update('timeline',${idx},'desc',this.value)"></div>
                <div class="item-row"><label>Impact</label><input value="${obj.impact || ''}" onchange="update('timeline',${idx},'impact',this.value)"></div>
                <div class="item-row"><label>Severity</label><select onchange="update('timeline',${idx},'severity',this.value)"><option ${obj.severity==='critical'?'selected':''}>critical</option><option ${obj.severity==='high'?'selected':''}>high</option><option ${obj.severity==='medium'?'selected':''}>medium</option></select></div>
                <button class="btn delete" onclick="deleteItem('timeline',${idx})">🗑️ Delete</button>
            </div>`;
        }
        
        function updateTime(idx, dateVal, timeVal) {
            if (!dateVal && !timeVal) return;
            let dateStr = '';
            if (dateVal) {
                const d = new Date(dateVal + 'T00:00:00');
                const months = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];
                dateStr = months[d.getMonth()] + ' ' + d.getDate();
            }
            const newTime = timeVal ? dateStr + ' ' + timeVal : dateStr;
            data.timeline[idx].time = newTime;
        }
        
        function update(key, idx, field, value) {
            data[key][idx][field] = value;
        }
        
        function deleteItem(key, idx) {
            data[key].splice(idx, 1);
            renderAll();
        }
        
        function addIP() {
            data.suspicious_ips = data.suspicious_ips || [];
            data.suspicious_ips.push({ip: '0.0.0.0', label: 'WOLF', type: 'ATTACKER', status: 'ACTIVE'});
            renderAll();
        }
        
        function addDomain() {
            data.phishing_domains = data.phishing_domains || [];
            data.phishing_domains.push({domain: 'example.com', type: 'PHISHING'});
            renderAll();
        }
        
        function addTimeline() {
            data.timeline = data.timeline || [];
            data.timeline.push({time: 'APR 23', title: 'New Event', tech: 'T0000', tactics: '[TA0000]', desc: 'Description', impact: 'Impact', severity: 'high'});
            renderAll();
        }
        
        function addRec() {
            data.recommendations = data.recommendations || [];
            data.recommendations.push({text: 'New recommendation', mitre: 'T0000', status: 'active'});
            renderAll();
        }
        
        function saveAll() {
            fetch('/api/data', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            }).then(r => r.json()).then(d => {
                alert('✅ All changes saved successfully!');
            });
        }
        
        loadData();
    </script>
</div>
</body>
</html>
'''

@app.route('/admin')
def admin():
    return render_template_string(ADMIN_TEMPLATE)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Map - {{ title }}</title>
    <link href="https://fonts.googleapis.com/css2?family=Black+Ops+One&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Rajdhani', sans-serif; background: #0a0a0a; min-height: 100vh; color: #b8c4ce; }
        .header { background: linear-gradient(180deg, #1a1a22 0%, #0f0f14 100%); padding: 15px 30px; border-bottom: 3px solid #5e9eff; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #c0c8d0; font-size: 22px; text-transform: uppercase; font-family: 'Black Ops One', cursive; }
        .container { padding: 20px 30px; }
        .upload-box { background: linear-gradient(145deg, #15151d, #0d0d12); border: 2px dashed #3a3a4a; border-radius: 10px; padding: 40px; text-align: center; margin-bottom: 30px; }
        .upload-box h3 { color: #5e9eff; margin-bottom: 15px; }
        .upload-box input[type="file"] { display: none; }
        .upload-box label { display: inline-block; background: #1a2535; color: #5e9eff; padding: 12px 25px; border-radius: 5px; cursor: pointer; border: 1px solid #5e9eff; }
        .upload-box label:hover { background: #253545; }
        .upload-box .btn { display: inline-block; background: #1a2535; color: #5e9eff; padding: 12px 25px; border-radius: 5px; cursor: pointer; border: 1px solid #5e9eff; margin: 10px 5px; }
        .map-container { background: #0d0d12; border: 1px solid #2a2a35; border-radius: 8px; padding: 20px; min-height: 500px; position: relative; }
        .node { position: absolute; background: #1a2535; border: 2px solid #3a3a4a; border-radius: 50%; padding: 15px 20px; cursor: move; text-align: center; transition: box-shadow 0.3s; }
        .node:hover { box-shadow: 0 0 20px rgba(94, 158, 255, 0.5); border-color: #5e9eff; }
        .node.dmz { border-color: #ff8800; }
        .node.internal { border-color: #5e9eff; }
        .node.external { border-color: #ff4444; }
        .node.compromised { border-color: #ff4444; background: #2a1515; }
        .node.server { border-radius: 8px; }
        .node-label { color: #c0c8d0; font-size: 12px; font-weight: bold; }
        .node-sublabel { color: #6a7585; font-size: 10px; }
        .connection { position: absolute; height: 2px; background: #3a3a4a; transform-origin: 0 50%; }
        .storyboard { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
        .story-card { background: linear-gradient(145deg, #15151d, #0d0d12); border: 1px solid #2a2a35; border-radius: 8px; padding: 20px; }
        .story-card h4 { color: #5e9eff; margin-bottom: 10px; font-size: 14px; }
        .story-card p { color: #7a8595; font-size: 12px; line-height: 1.5; }
        .story-card img { max-width: 100%; border-radius: 5px; margin-top: 10px; }
        .back-link { color: #5e9eff; text-decoration: none; margin-bottom: 20px; display: inline-block; }
        .legend { display: flex; gap: 20px; padding: 15px; background: #0d0d12; border-radius: 5px; margin-bottom: 20px; }
        .legend-item { display: flex; align-items: center; gap: 8px; }
        .legend-dot { width: 15px; height: 15px; border-radius: 50%; }
        .legend-dot.dmz { background: #ff8800; }
        .legend-dot.internal { background: #5e9eff; }
        .legend-dot.external { background: #ff4444; }
        .legend-dot.compromised { background: #ff4444; border: 2px solid #ff4444; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #1a1a22; border: 1px solid #2a2a35; border-radius: 5px; cursor: pointer; }
        .tab.active { background: #1a2535; border-color: #5e9eff; color: #5e9eff; }
        .sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: 50px; background: #0f0f14; border-right: 1px solid #2a2a35; padding: 20px 0; z-index: 1000; transition: width 0.3s ease; overflow: hidden; }
        .sidebar:hover { width: 200px; }
        .sidebar-item { display: flex; align-items: center; padding: 15px 15px; color: #7a8595; text-decoration: none; border-left: 3px solid transparent; transition: all 0.3s; white-space: nowrap; }
        .sidebar-item:hover { background: #1a1a22; color: #c0c8d0; }
        .sidebar-item.active { background: #1a1a22; color: #5e9eff; border-left-color: #5e9eff; }
        .sidebar-item span { min-width: 30px; font-size: 18px; }
        .main-content { margin-left: 50px; transition: margin-left 0.3s ease; }
    </style>
</head>
<body>
    <div class="sidebar">
        <a href="/" class="sidebar-item"><span>📊</span>Dashboard</a>
        <a href="/network-map" class="sidebar-item active"><span>🗺️</span>Network Map</a>
        <a href="/reports" class="sidebar-item"><span>📋</span>Reports</a>
        <a href="/admin" class="sidebar-item"><span>⚙️</span>Admin</a>
    </div>
    <div class="main-content">
    <div class="header">
        <h1>Network Map - Operation Digital Fortitude</h1>
    </div>
    <div class="container">
        <div class="tabs">
            <div class="tab active" onclick="showTab('map')">Network Map</div>
            <div class="tab" onclick="showTab('storyboard')">Storyboards</div>
        </div>
        <div id="map-view">
            <div class="upload-box">
                {% if success %}
                <h3 style="color:#5e9eff;">✅ Network Diagram Uploaded Successfully!</h3>
                <p style="color:#5e9eff;margin:15px 0;">Your network map has been parsed and displayed below.</p>
                {% elif error %}
                <h3 style="color:#ff4444;">❌ Upload Failed</h3>
                <p style="color:#ff4444;margin:15px 0;">Error: {{ error }}</p>
                {% else %}
                <h3>📁 Upload draw.io Network Diagram</h3>
                {% endif %}
                <form method="post" action="/api/upload-map" enctype="multipart/form-data">
                    <input type="file" name="file" accept=".xml" style="display:block;margin:20px auto;padding:10px;background:#1a2535;color:#c0c8d0;border:1px solid #5e9eff;border-radius:5px;">
                    <button type="submit" style="background:#5e9eff;color:#0a0a0a;padding:12px 25px;border:none;border-radius:5px;font-weight:bold;cursor:pointer;">UPLOAD XML</button>
                </form>
                <p style="color:#6a7585;margin-top:15px;font-size:13px;">Upload a draw.io XML file to visualize your network topology</p>
            </div>
            <div class="legend">
                <div class="legend-item"><div class="legend-dot external"></div> External</div>
                <div class="legend-item"><div class="legend-dot dmz"></div> DMZ</div>
                <div class="legend-item"><div class="legend-dot internal"></div> Internal</div>
                <div class="legend-item"><div class="legend-dot compromised"></div> Compromised</div>
            </div>
            <div class="map-container" id="mapContainer">
                {% if nodes and nodes|length > 0 %}
                    {% for node in nodes %}
                    <div class="node {{ node.type }}" style="left: {{ node.x }}px; top: {{ node.y }}px;">
                        <div class="node-label">{{ node.label }}</div>
                        {% if node.ip %}<div class="node-sublabel">{{ node.ip }}</div>{% endif %}
                    </div>
                    {% endfor %}
                {% else %}
                <p style="color:#6a7585;text-align:center;padding:100px;">No network map uploaded yet.<br>Upload a draw.io XML diagram above to visualize your network.</p>
                {% endif %}
            </div>
        </div>
        <div id="storyboard-view" style="display:none;">
            <div class="storyboard">
                <div class="story-card">
                    <h4>🐺 Phase 1: Initial Access</h4>
                    <p>Attacker conducts spear phishing campaign targeting admin, sales, and operations departments.</p>
                </div>
                <div class="story-card">
                    <h4>🐑 Phase 2: Execution</h4>
                    <p>Malicious payload executes via email attachment/link. Remote shell established via named pipes.</p>
                </div>
                <div class="story-card">
                    <h4>🐑 Phase 3: Persistence</h4>
                    <p>Attacker creates service entries and modifies registry for long-term access.</p>
                </div>
                <div class="story-card">
                    <h4>🐑 Phase 4: Privilege Escalation</h4>
                    <p>DLL injection elevates privileges. Attacker harvests credentials from memory.</p>
                </div>
                <div class="story-card">
                    <h4>🐑 Phase 5: Lateral Movement</h4>
                    <p>PsExec used to spread to Admin/Sales/Ops subnets. Shared drives created.</p>
                </div>
                <div class="story-card">
                    <h4>🐑 Phase 6: Defense Evasion</h4>
                    <p>Artifacts placed in TMP folder and deleted. Forensics deliberately obscured.</p>
                </div>
            </div>
        </div>
    </div>
    <script>
        function showTab(tab) {
            document.getElementById('map-view').style.display = tab === 'map' ? 'block' : 'none';
            document.getElementById('storyboard-view').style.display = tab === 'storyboard' ? 'block' : 'none';
        }
    </script>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return send_file(DASHBOARD_PATH)

@app.route('/network-map')
def network_map():
    nodes = load_parsed_nodes()
    success = request.args.get('success')
    error = request.args.get('error')
    return render_template_string(HTML_TEMPLATE, title="Network Map", nodes=nodes, success=success, error=error)

def load_parsed_nodes():
    map_file = os.path.join(UPLOAD_FOLDER, 'network_map.xml')
    if not os.path.exists(map_file):
        return []
    
    try:
        with open(map_file, 'r') as f:
            content = f.read()
        
        import re
        from html import unescape
        
        nodes = []
        
        # Find all vertex cells with x and y coordinates
        # Pattern looks for mxCell with vertex=1 that has x= and y= attributes directly
        cells = re.findall(r'<mxCell([^>]*vertex="1"[^>]*x="[0-9]+"[^>]*y="[0-9]+"[^>]*)>', content)
        
        for cell in cells:
            value_match = re.search(r'value="([^"]+)"', cell)
            x_match = re.search(r'x="([^"]+)"', cell)
            y_match = re.search(r'y="([^"]+)"', cell)
            style_match = re.search(r'style="([^"]+)"', cell)
            
            if not (value_match and x_match and y_match):
                continue
            
            value = value_match.group(1)
            x = x_match.group(1)
            y = y_match.group(1)
            style = style_match.group(1) if style_match else ''
            
            # Unescape HTML entities
            value = unescape(value)
            # Remove HTML tags
            clean_value = re.sub(r'<[^>]+>', '', value).strip()
            
            if not clean_value or len(clean_value) < 3:
                continue
            
            node_type = 'internal'
            style_lower = style.lower()
            
            if 'dashed' in style_lower or 'perimeter' in style_lower:
                node_type = 'dmz'
            elif 'rounded' in style_lower or 'shape=process' in style_lower:
                node_type = 'dmz'
            elif 'rhombus' in style_lower:
                node_type = 'dmz'
            elif 'ellipse' in style_lower:
                node_type = 'internal'
            
            try:
                x_pos = int(x) // 3
                y_pos = int(y) // 3
            except:
                x_pos = 100
                y_pos = 100
            
            nodes.append({
                'label': clean_value[:25],
                'ip': clean_value if '.' in clean_value and re.match(r'^[\d.]+$', clean_value) else '',
                'type': node_type,
                'x': max(50, min(x_pos, 750)),
                'y': max(50, min(y_pos, 450))
            })
        
        # If we have very few nodes, try extracting all IPs from the diagram
        if len(nodes) < 5:
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, content)
            seen = set()
            for ip in ips:
                if ip not in seen and len(nodes) < 20:
                    seen.add(ip)
                    nodes.append({
                        'label': ip,
                        'ip': ip,
                        'type': 'internal',
                        'x': 100 + len(nodes) * 90,
                        'y': 200 + (len(nodes) % 3) * 100
                    })
        
        return nodes[:30]
    except Exception as e:
        print(f"Error parsing XML: {e}")
        import traceback
        traceback.print_exc()
        return [{'label': 'Error', 'ip': '', 'type': 'internal', 'x': 300, 'y': 250}]

@app.route('/api/upload-map', methods=['POST'])
def upload_map():
    if 'file' not in request.files:
        return '''
        <!DOCTYPE html>
        <html><head><meta http-equiv="refresh" content="0;url=/network-map?error=no_file"></head></html>
        '''
    
    file = request.files['file']
    if file.filename == '':
        return '''
        <!DOCTYPE html>
        <html><head><meta http-equiv="refresh" content="0;url=/network-map?error=no_file"></head></html>
        '''
    
    if file and file.filename.endswith('.xml'):
        filename = os.path.join(UPLOAD_FOLDER, 'network_map.xml')
        file.save(filename)
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Upload Success</title>
            <link href="https://fonts.googleapis.com/css2?family=Black+Ops+One&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
            <style>
                body { font-family: 'Rajdhani', sans-serif; background: #0a0a0a; color: #c0c8d0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                .success { text-align: center; padding: 40px; background: linear-gradient(145deg, #15151d, #0d0d12); border: 2px solid #5e9eff; border-radius: 10px; }
                .success h1 { color: #5e9eff; font-family: 'Black Ops One', cursive; }
                .success p { color: #7a8595; margin: 20px 0; }
                .success .count { color: #5e9eff; font-size: 48px; font-weight: bold; }
                .redirect { color: #6a7585; font-size: 14px; }
            </style>
        </head>
        <body>
            <div class="success">
                <h1>✅ UPLOAD SUCCESSFUL</h1>
                <p class="count">1</p>
                <p>Network diagram uploaded and parsed</p>
                <p class="redirect">Redirecting to network map...</p>
            </div>
            <meta http-equiv="refresh" content="3;url=/network-map">
        </body>
        </html>
        '''
    
    return '''
    <!DOCTYPE html>
    <html><head><meta http-equiv="refresh" content="0;url=/network-map?error=invalid_type"></head></html>
    '''

@app.route('/api/iocs')
def iocs():
    return jsonify({
        "ips": [
            {"ip": "1.178.224.2", "type": "ATTACKER", "first_seen": "2026-04-21", "status": "BLOCKED"},
            {"ip": "1.20.0.15", "type": "C2", "first_seen": "2026-04-21", "status": "BLOCKED"},
            {"ip": "1.146.108.60", "type": "ATTACKER", "first_seen": "2026-04-19", "status": "BLOCKED"},
            {"ip": "192.108.28.105", "type": "ATTACKER", "first_seen": "2026-04-19", "status": "BLOCKED"},
            {"ip": "104.53.221.1", "type": "SCANNER", "first_seen": "2026-04-17"},
            {"ip": "192.108.28.108", "type": "C2", "first_seen": "2026-04-20"},
            {"ip": "54.59.3.3", "type": "ATTACKER", "first_seen": "2026-04-17"}
        ],
        "domains": [
            {"domain": "technexus.pl", "type": "C2", "first_seen": "2026-04-21"},
            {"domain": "ctldl.windowsupdate.com", "type": "C2", "first_seen": "2026-04-21"},
            {"domain": "hobbyinitiative.gov", "type": "PHISHING", "first_seen": "2026-04-20"}
        ],
        "hashes": [
            {"hash": "a1b2c3d4e5f6789012345678abcdef12", "malware": "ServiceV1.exe", "type": "EXE", "status": "REMOVED"},
            {"hash": "deadbeef1234567890abcdef01234567", "malware": "ServiceV2.exe", "type": "EXE", "status": "REMOVED"},
            {"hash": "cafebabe8765432101234567890abcdef", "malware": "Document.pdf.exe", "type": "EXE", "status": "REMOVED"},
            {"hash": "baadf00d1234567890abcdef01234567", "malware": "meeting.rar", "type": "RAR", "status": "REMOVED"}
        ]
    })

REPORTS_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IR Reports - Operation Digital Fortitude</title>
    <link href="https://fonts.googleapis.com/css2?family=Black+Ops+One&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Rajdhani', sans-serif; background: #0a0a0a; min-height: 100vh; color: #b8c4ce; }
        .header { background: linear-gradient(180deg, #1a1a22 0%, #0f0f14 100%); padding: 15px 30px; border-bottom: 3px solid #5e9eff; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #c0c8d0; font-size: 22px; text-transform: uppercase; font-family: 'Black Ops One', cursive; }
        .container { padding: 20px 30px; }
        .sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: 50px; background: #0f0f14; border-right: 1px solid #2a2a35; padding: 20px 0; z-index: 1000; transition: width 0.3s ease; overflow: hidden; }
        .sidebar:hover { width: 200px; }
        .sidebar-item { display: flex; align-items: center; padding: 15px 15px; color: #7a8595; text-decoration: none; border-left: 3px solid transparent; transition: all 0.3s; white-space: nowrap; }
        .sidebar-item:hover { background: #1a1a22; color: #c0c8d0; }
        .sidebar-item.active { background: #1a1a22; color: #5e9eff; border-left-color: #5e9eff; }
        .sidebar-item span { min-width: 30px; font-size: 18px; }
        .main-content { margin-left: 50px; transition: margin-left 0.3s ease; }
        .report-card { background: linear-gradient(145deg, #15151d, #0d0d12); border: 1px solid #2a2a35; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .report-header { display: flex; justify-content: space-between; border-bottom: 1px solid #2a2a35; padding-bottom: 10px; margin-bottom: 15px; }
        .report-header h3 { color: #5e9eff; font-size: 14px; }
        .report-header .analyst { color: #ff8800; font-size: 12px; }
        .report-header .date { color: #6a7585; font-size: 12px; }
        .report-subject { color: #d0d8e0; font-size: 16px; font-weight: bold; margin-bottom: 10px; }
        .report-meta { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; margin-bottom: 15px; }
        .meta-item { background: #0d0d12; padding: 8px 12px; border-radius: 4px; font-size: 12px; }
        .meta-label { color: #6a7585; font-size: 10px; text-transform: uppercase; }
        .meta-value { color: #c0c8d0; margin-top: 4px; }
        .report-summary { color: #7a8595; font-size: 13px; line-height: 1.6; }
        .critical { border-left: 3px solid #ff4444; }
        .high { border-left: 3px solid #ff8800; }
        .medium { border-left: 3px solid #ffe66d; }
        .search-box { background: linear-gradient(145deg, #15151d, #0d0d12); border: 1px solid #2a2a35; border-radius: 8px; padding: 15px; margin-bottom: 20px; }
        .search-box input { width: 100%; padding: 10px; background: #0d0d12; border: 1px solid #2a2a35; color: #c0c8d0; border-radius: 5px; font-size: 14px; }
        .filters { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .filter-btn { padding: 8px 15px; background: #1a1a22; border: 1px solid #2a2a35; border-radius: 5px; color: #7a8595; cursor: pointer; font-size: 12px; }
        .filter-btn.active { background: #1a2535; border-color: #5e9eff; color: #5e9eff; }
    </style>
</head>
<body>
    <div class="sidebar">
        <a href="/" class="sidebar-item"><span>📊</span>Dashboard</a>
        <a href="/network-map" class="sidebar-item"><span>🗺️</span>Network Map</a>
        <a href="/reports" class="sidebar-item active"><span>📋</span>IR Reports</a>
        <a href="/admin" class="sidebar-item"><span>⚙️</span>Admin</a>
    </div>
    <div class="main-content">
    <div class="header">
        <h1>IR Reports - Operation Digital Fortitude</h1>
    </div>
    <div class="container">
        <div class="search-box">
            <input type="text" id="searchInput" placeholder="Search reports by IP, subject, analyst, or keywords...">
        </div>
        <div class="filters">
            <div class="filter-btn active" onclick="filterReports('all')">All</div>
            <div class="filter-btn" onclick="filterReports('critical')">Critical</div>
            <div class="filter-btn" onclick="filterReports('high')">High</div>
            <div class="filter-btn" onclick="filterReports('malware')">Malware</div>
            <div class="filter-btn" onclick="filterReports('lateral')">Lateral Movement</div>
            <div class="filter-btn" onclick="filterReports('recon')">Reconnaissance</div>
        </div>
        
        <div id="reportsContainer">
            <div class="report-card critical" data-keywords="malware service reverse shell document.pdf">
                <div class="report-header">
                    <h3>IR-2026-0420-A</h3>
                    <span class="analyst">Analyst: Perez</span>
                    <span class="date">Apr 20, 2026 2:28 PM</span>
                </div>
                <div class="report-subject">Document.pdf.exe - Malicious File Entry Point</div>
                <div class="report-meta">
                    <div class="meta-item"><div class="meta-label">Operation</div><div class="meta-value">AT26</div></div>
                    <div class="meta-item"><div class="meta-label">Discovery DTG</div><div class="meta-value">Apr 20 @ 13:00</div></div>
                    <div class="meta-item"><div class="meta-label">Hostile IPs</div><div class="meta-value">192.108.28.108, hobbyinitiative.gov</div></div>
                    <div class="meta-item"><div class="meta-label">Affected Hosts</div><div class="meta-value">cc-ops-1, cc-ops-7, cc-sales-1, cc-admin-1</div></div>
                </div>
                <div class="report-summary">
                    <strong>Summary:</strong> Malicious file (Document.pdf.exe / backup2.exe) used as entry point, downloaded from Outlook via WinRAR, creates reverse shell connection to 192.108.28.108:443. Creates ServiceV1.exe and ServiceV4.exe.<br><br>
                    <strong>Tools:</strong> Document.pdf.exe, ServiceV1.exe, ServiceV4.exe, WinRAR.exe<br>
                    <strong>DNS Queries:</strong> hobbyinitiative.gov, ctldl.windowsupdate.com<br>
                    <strong>Users Affected:</strong> euginia.potts, alec.mercado, lexi.walsh, monroe.lang, kelli.barlett, preston.camacho
                </div>
            </div>
            
            <div class="report-card critical" data-keywords="ssh lateral service servicev1 servicev2">
                <div class="report-header">
                    <h3>IR-2026-0420-B</h3>
                    <span class="analyst">Analyst: Perez</span>
                    <span class="date">Apr 21, 2026 8:42 AM</span>
                </div>
                <div class="report-subject">ServiceV1 & ServiceV4 SSH Connections / Reverse Shell</div>
                <div class="report-meta">
                    <div class="meta-item"><div class="meta-label">Operation</div><div class="meta-value">AT26</div></div>
                    <div class="meta-item"><div class="meta-label">Discovery DTG</div><div class="meta-value">Apr 19 @ 13:55</div></div>
                    <div class="meta-item"><div class="meta-label">Hostile IPs</div><div class="meta-value">205.202.5.1, 201.220.0.22, ctldl.windowsupdate.com</div></div>
                    <div class="meta-item"><div class="meta-label">Compromised Hosts</div><div class="meta-value">CC-SALES-7, CC-ADMIN-7</div></div>
                </div>
                <div class="report-summary">
                    <strong>Summary:</strong> ServiceV1.exe (monroe.lang) connected via SSH to 205.202.5.1:22. ServiceV2.exe (alec.mercado) connected to 201.220.0.22:443. Alert: Service running from unbacked memory, AMSI/WLDP bypass detected.<br><br>
                    <strong>Tools:</strong> ServiceV1.exe, ServiceV2.exe<br>
                    <strong>DNS Queries:</strong> ctldl.windowsupdate.com, technexus.pl<br>
                    <strong>Users:</strong> monroe.lang, alec.mercado
                </div>
            </div>
            
            <div class="report-card high" data-keywords="kerberoasting kerberos ticket">
                <div class="report-header">
                    <h3>IR-2026-0417-A</h3>
                    <span class="analyst">Analyst: SPC Picou</span>
                    <span class="date">Apr 17, 2026 1:38 PM</span>
                </div>
                <div class="report-subject">Kerberoasting on Domain Controller</div>
                <div class="report-meta">
                    <div class="meta-item"><div class="meta-label">Operation</div><div class="meta-value">AT26</div></div>
                    <div class="meta-item"><div class="meta-label">Activity DTG</div><div class="meta-value">Apr 16, 2026 @ 02:57</div></div>
                    <div class="meta-item"><div class="meta-label">Hostile IP</div><div class="meta-value">54.59.3.3</div></div>
                    <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">CC-DC (205.202.2.5)</div></div>
                </div>
                <div class="report-summary">
                    <strong>Summary:</strong> Kerberoasting attack detected from 54.59.3.3 targeting domain controller. Weak RC4 encryption (0x17) used for ticket granting tickets. Compromised service accounts: svc_exchange, svc_mail, svc_backup, svc_app, svc_mssql, krbtgt.<br><br>
                    <strong>Ports:</strong> 48888-48938<br>
                    <strong>Query:</strong> winlog.event_data.ticketencryptiontype : 0x17
                </div>
            </div>
            
            <div class="report-card high" data-keywords="smb pipe reverse shell lateral">
                <div class="report-header">
                    <h3>IR-2026-0419-A</h3>
                    <span class="analyst">Analyst: Perez</span>
                    <span class="date">Apr 19, 2026 11:10 AM</span>
                </div>
                <div class="report-subject">SMB Share Access - Potential Reverse Shell</div>
                <div class="report-meta">
                    <div class="meta-item"><div class="meta-label">Operation</div><div class="meta-value">AT26</div></div>
                    <div class="meta-item"><div class="meta-label">Activity DTG</div><div class="meta-value">Apr 19 @ 04:00</div></div>
                    <div class="meta-item"><div class="meta-label">Hostile IP</div><div class="meta-value">1.146.108.60</div></div>
                    <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">205.202.1.2 (CC-SMTP)</div></div>
                </div>
                <div class="report-summary">
                    <strong>Summary:</strong> External IP 1.146.108.60 accessing SMB pipe at \\\\205.202.1.2\\IPC$. Multiple instances observed. Creation of shared pipe indicates potential reverse shell capability.<br><br>
                    <strong>Protocol:</strong> SMB<br>
                    <strong>Port:</strong> 445
                </div>
            </div>
            
            <div class="report-card medium" data-keywords="smtp phishing email helo lateral">
                <div class="report-header">
                    <h3>IR-2026-0419-B</h3>
                    <span class="analyst">Analyst: Thomas Greenslit</span>
                    <span class="date">Apr 19, 2026 12:25 PM</span>
                </div>
                <div class="report-subject">Suspicious SMTP Traffic - Phishing Campaign</div>
                <div class="report-meta">
                    <div class="meta-item"><div class="meta-label">Operation</div><div class="meta-value">AT26</div></div>
                    <div class="meta-item"><div class="meta-label">Activity DTG</div><div class="meta-value">Apr 19 @ 04:25</div></div>
                    <div class="meta-item"><div class="meta-label">Hostile IP</div><div class="meta-value">1.146.108.60</div></div>
                    <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">CC-SMTP (205.202.1.2)</div></div>
                </div>
                <div class="report-summary">
                    <strong>Summary:</strong> 1.146.108.60 sent emails containing just "HELO" to multiple users via SMTP. Messages from user@example.com. No attachments. May be identifying targets for further phishing.<br><br>
                    <strong>Ports:</strong> Random high ports (36600s)<br>
                    <strong>Note:</strong> Suricata rule created to detect further SMTP traffic from this IP.
                </div>
            </div>
            
            <div class="report-card medium" data-keywords="ping sweep recon icmp scanner">
                <div class="report-header">
                    <h3>IR-2026-0420-C</h3>
                    <span class="analyst">Analyst: Perez</span>
                    <span class="date">Apr 20, 2026 7:44 AM</span>
                </div>
                <div class="report-subject">Ping Sweep - External IP Scanning</div>
                <div class="report-meta">
                    <div class="meta-item"><div class="meta-label">Operation</div><div class="meta-value">AT26</div></div>
                    <div class="meta-item"><div class="meta-label">Activity DTG</div><div class="meta-value">Apr 20 @ 07:39</div></div>
                    <div class="meta-item"><div class="meta-label">Hostile IP</div><div class="meta-value">104.53.221.1</div></div>
                    <div class="meta-item"><div class="meta-label">Target Range</div><div class="meta-value">205.202.[2-8].0</div></div>
                </div>
                <div class="report-summary">
                    <strong>Summary:</strong> Ping sweep from external IP 104.53.221.1 targeting DMZ subnet 205.202.2-8.0. ICMP type 1 code 3.<br><br>
                    <strong>Protocol:</strong> ICMP
                </div>
            </div>
            
            <div class="report-card medium" data-keywords="ping sweep recon icmp scanner">
                <div class="report-header">
                    <h3>IR-2026-0419-C</h3>
                    <span class="analyst">Analyst: Perez</span>
                    <span class="date">Apr 19, 2026 10:37 AM</span>
                </div>
                <div class="report-subject">Ping Sweep - Network Reconnaissance</div>
                <div class="report-meta">
                    <div class="meta-item"><div class="meta-label">Operation</div><div class="meta-value">AT26</div></div>
                    <div class="meta-item"><div class="meta-label">Activity DTG</div><div class="meta-value">Apr 19 @ 10:01</div></div>
                    <div class="meta-item"><div class="meta-label">Hostile IP</div><div class="meta-value">104.53.221.1</div></div>
                    <div class="meta-item"><div class="meta-label">Target Range</div><div class="meta-value">205.202.[3-8].0</div></div>
                </div>
                <div class="report-summary">
                    <strong>Summary:</strong> Ping sweep from external IP scanning target subnet 205.202.3-8.0.<br><br>
                    <strong>Protocol:</strong> ICMP
                </div>
            </div>
            
            <div class="report-card medium" data-keywords="port scan recon">
                <div class="report-header">
                    <h3>IR-2026-0419-D</h3>
                    <span class="analyst">Analyst: Perez</span>
                    <span class="date">Apr 19, 2026 9:29 AM</span>
                </div>
                <div class="report-subject">Port Scan - CC-SMTP Server</div>
                <div class="report-meta">
                    <div class="meta-item"><div class="meta-label">Operation</div><div class="meta-value">AT26</div></div>
                    <div class="meta-item"><div class="meta-label">Activity DTG</div><div class="meta-value">Apr 19 @ 03:13</div></div>
                    <div class="meta-item"><div class="meta-label">Hostile IP</div><div class="meta-value">1.146.108.60</div></div>
                    <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">205.202.1.2 (CC-SMTP)</div></div>
                </div>
                <div class="report-summary">
                    <strong>Summary:</strong> Port scan on SMTP server (205.202.1.2). Scanning high port range from random source ports (23872-46338).<br><br>
                    <strong>Ports:</strong> 0, 21, 22, 25, 110, 139, 445, 1720, 4531
                </div>
            </div>
            
            <div class="report-card medium" data-keywords="failed logon authentication">
                <div class="report-header">
                    <h3>IR-2026-0419-E</h3>
                    <span class="analyst">Analyst: Perez</span>
                    <span class="date">Apr 19, 2026 2:13 PM</span>
                </div>
                <div class="report-subject">Failed Logon Attempts</div>
                <div class="report-meta">
                    <div class="meta-item"><div class="meta-label">Operation</div><div class="meta-value">AT26</div></div>
                    <div class="meta-item"><div class="meta-label">Activity DTG</div><div class="meta-value">Apr 19 @ 04:16</div></div>
                    <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">205.202.2.5 (CC-DC)</div></div>
                </div>
                <div class="report-summary">
                    <strong>Summary:</strong> Failed login attempts detected against multiple accounts.<br><br>
                    <strong>Attempts:</strong> Administrator: 11, larry.jones: 2, bettye.rush: 1, sammy.curtis: 1
                </div>
            </div>
            
            <div class="report-card medium" data-keywords="ping sweep recon icmp scanner">
                <div class="report-header">
                    <h3>IR-2026-0418-F</h3>
                    <span class="analyst">Analyst: SPC Picou</span>
                    <span class="date">Apr 19, 2026 8:59 AM</span>
                </div>
                <div class="report-subject">Ping Sweep - 53 Hosts Scanned</div>
                <div class="report-meta">
                    <div class="meta-item"><div class="meta-label">Operation</div><div class="meta-value">AT26</div></div>
                    <div class="meta-item"><div class="meta-label">Activity DTG</div><div class="meta-value">Apr 18-19, 2026</div></div>
                    <div class="meta-item"><div class="meta-label">Hostile IP</div><div class="meta-value">104.53.221.1</div></div>
                    <div class="meta-item"><div class="meta-label">Target Range</div><div class="meta-value">205.202.0.0/16</div></div>
                </div>
                <div class="report-summary">
                    <strong>Summary:</strong> Ping sweep from 104.53.221.1 scanning 53 hosts in 205.202.0.0/16 subnet. ICMP ports 3 and 1.<br><br>
                    <strong>Tools:</strong> ping
                </div>
            </div>
        </div>
    </div>
    <script>
        document.getElementById('searchInput').addEventListener('input', function(e) {
            const search = e.target.value.toLowerCase();
            document.querySelectorAll('.report-card').forEach(function(card) {
                const text = card.textContent.toLowerCase();
                card.style.display = text.includes(search) ? 'block' : 'none';
            });
        });
        
        function filterReports(type) {
            document.querySelectorAll('.filter-btn').forEach(function(btn) {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            document.querySelectorAll('.report-card').forEach(function(card) {
                if (type === 'all') {
                    card.style.display = 'block';
                } else if (type === 'critical') {
                    card.className = 'report-card critical';
                } else if (type === 'high') {
                    card.className = 'report-card high';
                } else {
                    const keywords = card.getAttribute('data-keywords') || '';
                    card.style.display = keywords.includes(type) ? 'block' : 'none';
                }
            });
        }
    </script>
    </div>
</body>
</html>
'''

@app.route('/reports')
def reports():
    return render_template_string(REPORTS_TEMPLATE)

@app.route('/api/stats')
def stats():
    return jsonify({
        "active_iocs": 47,
        "compromised_hosts": 12,
        "campaigns": 8,
        "attribution_score": 94,
        "threat_level": "CRITICAL"
    })

if __name__ == '__main__':
    print("=" * 50)
    print("APT 28 Threat Dashboard")
    print("Running on http://0.0.0.0:8089")
    print("=" * 50)
    try:
        app.run(host='0.0.0.0', port=8089, debug=False, use_reloader=False, threaded=True)
    except Exception as e:
        print(f"Server error: {e}")