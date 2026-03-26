/* app.js — frontend logic */

const EMOJI_LIST = ["😀","😂","😍","🥰","😎","🤔","😢","😡","👍","👎","🙏","🎉","🔥","❤️","💯","✅","🚀","🌟","😴","🤣","👀","💬","📎","🖼️"];
const AVATAR_COLORS = ["#e74c3c","#e67e22","#f1c40f","#2ecc71","#1abc9c","#3498db","#9b59b6","#e91e63","#00bcd4","#8bc34a","#ff5722","#607d8b"];

let myNodeId = "";
let myAlias = "";
let currentPeerId = null;
let peers = {
    '#BROADCAST': { node_id: '#BROADCAST', alias: '🌍 频道全体 (群聊)', unread: 0, secure: true }
};        // node_id -> peer_info
let peerMessages = {
    '#BROADCAST': []
}; // node_id -> [msg_obj, ...]

/* ==================== INIT & EVENT BRIDGE ==================== */
window.addEventListener('pywebviewready', async () => {
    // pywebview is ready
    const cfg = await window.pywebview.api.get_config();
    if(cfg) {
        document.getElementById('cfg-alias').value = cfg.node_alias;
        document.getElementById('cfg-netid').value = cfg.network_id;
        document.getElementById('cfg-udp').value = cfg.udp_discovery_port;
        document.getElementById('cfg-tcp').value = cfg.tcp_listen_port;
    }
});

window.on_event = function(event_name, data) {
    console.log("Event from Python:", event_name, data);
    if (event_name === "peer_discovered") {
        updatePeer(data);
    } else if (event_name === "message_received" || event_name === "message_sent") {
        handleIncomingMessage(data);
    } else if (event_name === "file_received") {
        handleFileReceived(data);
    } else if (event_name === "session_established") {
        const p = peers[data.peer_id];
        if(p) p.secure = true;
        if(currentPeerId === data.peer_id) {
            document.getElementById('current-peer-status').classList.remove('hidden');
        }
    }
};

document.getElementById('chat-messages').addEventListener('click', (e) => {
    const node = e.target.closest('[data-path]');
    if (node && node.dataset.path) {
        window.pywebview.api.open_file(node.dataset.path);
    }
});

/* ==================== LOGIN ==================== */
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const alias = document.getElementById('cfg-alias').value;
    const netid = document.getElementById('cfg-netid').value;
    const udp = parseInt(document.getElementById('cfg-udp').value);
    const tcp = parseInt(document.getElementById('cfg-tcp').value);

    const res = await window.pywebview.api.login(alias, netid, udp, tcp);
    if (res.status === 'ok') {
        myNodeId = res.node_id;
        myAlias = res.alias;
        document.getElementById('login-view').classList.remove('active');
        document.getElementById('main-view').classList.add('active');
        document.getElementById('fingerprint-out').value = await window.pywebview.api.get_fingerprint();
        renderSidebar();
        selectPeer('#BROADCAST');
    } else {
        alert("登录失败: " + res.error);
    }
});


/* ==================== SIDEBAR ==================== */
function getAvatarColor(id) {
    if(!id) return AVATAR_COLORS[0];
    const idx = parseInt(id.substring(0,4), 16) % AVATAR_COLORS.length;
    return AVATAR_COLORS[idx];
}
function getInitials(alias) {
    if(!alias) return "??";
    const parts = alias.trim().split(' ');
    if(parts.length >= 2) return (parts[0][0] + parts[parts.length-1][0]).toUpperCase();
    return alias.substring(0,2).toUpperCase();
}

function updatePeer(peer) {
    peers[peer.node_id] = peer;
    if(!peerMessages[peer.node_id]) peerMessages[peer.node_id] = [];
    renderSidebar();
}

function renderSidebar() {
    const query = document.getElementById('search-input').value.toLowerCase();
    const list = document.getElementById('contact-list');
    list.innerHTML = "";

    const peerArray = Object.values(peers);
    peerArray.sort((a,b) => {
        if(a.node_id === '#BROADCAST') return -1;
        if(b.node_id === '#BROADCAST') return 1;
        return 0;
    });

    peerArray.forEach(p => {
        if(query && p.node_id !== '#BROADCAST' && !p.alias.toLowerCase().includes(query) && !p.node_id.toLowerCase().includes(query)) return;
        
        const isSel = (p.node_id === currentPeerId);
        const li = document.createElement('li');
        li.className = `contact-item ${isSel?'selected':''}`;
        li.onclick = () => selectPeer(p.node_id);
        
        const unread = p.unread > 0 ? `<span class="badge">${p.unread}</span>` : "";
        
        li.innerHTML = `
            <div class="avatar" style="background:${getAvatarColor(p.node_id)}">${getInitials(p.alias)}</div>
            <div class="contact-info">
                <div class="contact-name-row">
                    <span class="contact-name">${p.alias}</span>
                    <span class="contact-time">${p.last_time || ''}</span>
                </div>
                <div class="contact-preview">${p.last_msg || '新发现节点'} ${unread}</div>
            </div>
        `;
        list.appendChild(li);
    });
}

document.getElementById('search-input').addEventListener('input', renderSidebar);


/* ==================== CHAT ==================== */
function selectPeer(node_id) {
    currentPeerId = node_id;
    const p = peers[node_id];
    p.unread = 0;
    renderSidebar();

    document.getElementById('current-peer-name').innerText = p.alias;
    if(p.secure) document.getElementById('current-peer-status').classList.remove('hidden');
    else document.getElementById('current-peer-status').classList.add('hidden');
    
    document.querySelector('.empty-state').classList.add('hidden');
    const input = document.getElementById('chat-input');
    input.disabled = false;
    input.placeholder = "输入消息 (Enter 发送)...";
    
    renderChatArea();
}

function handleIncomingMessage(msg) {
    if (msg.is_broadcast) {
        peerMessages['#BROADCAST'].push(msg);
        peers['#BROADCAST'].last_msg = msg.is_file ? "[文件]" : msg.content.substring(0, 20);
        const d = new Date(msg.timestamp * 1000);
        peers['#BROADCAST'].last_time = `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}`;
        if(currentPeerId !== '#BROADCAST' && !msg.is_me) peers['#BROADCAST'].unread = (peers['#BROADCAST'].unread || 0) + 1;
        
        renderSidebar();
        if(currentPeerId === '#BROADCAST') renderChatArea();
        if (msg.is_me) return;
        return;
    }

    // msg: {sender_id, content, timestamp, alias, is_me, is_file, file_path, file_name, is_broadcast}
    const targetPeer = msg.is_me ? currentPeerId : msg.sender_id; // if I sent it, save in current peer's log
    if(!targetPeer) return;

    if(!peerMessages[targetPeer]) peerMessages[targetPeer] = [];
    peerMessages[targetPeer].push(msg);
    
    // update preview
    if(peers[targetPeer]) {
        peers[targetPeer].last_msg = msg.is_file ? "[文件]" : msg.content.substring(0, 20);
        const d = new Date(msg.timestamp * 1000);
        peers[targetPeer].last_time = `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}`;
        if(targetPeer !== currentPeerId) peers[targetPeer].unread = (peers[targetPeer].unread || 0) + 1;
        renderSidebar();
    }

    if(currentPeerId === targetPeer) {
        renderChatArea();
    }
}

function handleFileReceived(data) {
    // Treat as incoming msg
    handleIncomingMessage({
        sender_id: data.sender_id,
        alias: peers[data.sender_id] ? peers[data.sender_id].alias : data.sender_id,
        content: `已接收: ${data.file_name}`,
        timestamp: Math.floor(Date.now()/1000),
        is_me: false,
        is_file: true,
        file_path: data.file_path,
        file_name: data.file_name
    });
}

function renderChatArea() {
    const list = document.getElementById('chat-messages');
    // Keep empty state element, clear others
    const emptyState = list.querySelector('.empty-state');
    list.innerHTML = "";
    list.appendChild(emptyState);

    const msgs = peerMessages[currentPeerId] || [];
    msgs.forEach(m => {
        const isMe = m.is_me;
        const alias = isMe ? myAlias : m.alias;
        const color = getAvatarColor(isMe ? myNodeId : m.sender_id);
        const init = getInitials(alias);
        
        const d = new Date(m.timestamp * 1000);
        const timeStr = `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}`;

        let contentHtml = "";
        if(m.is_file) {
            contentHtml = `
                <div class="file-attachment" data-path="${m.file_path.replace(/"/g, '&quot;')}">
                    <span class="file-icon">📎</span>
                    <span class="file-name">${m.file_name}</span>
                </div>
            `;
        } else {
            // simple image check
            const str = m.content.trim();
            if(str.match(/\.(jpeg|jpg|png|gif|webp)$/i) && str.startsWith("/")) {
                contentHtml = `<img src="file://${str}" class="img-preview" data-path="${str.replace(/"/g, '&quot;')}">`;
            } else {
                contentHtml = m.content.replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\n/g, "<br>");
            }
        }

        const div = document.createElement('div');
        div.className = `message-row ${isMe ? 'me' : 'peer'}`;
        div.innerHTML = `
            <div class="avatar msg-avatar" style="background:${color}">${init}</div>
            <div class="msg-content">
                <div class="msg-name">${alias}</div>
                <div class="msg-bubble">${contentHtml}</div>
                <div class="msg-time">${timeStr}</div>
            </div>
        `;
        list.appendChild(div);
    });

    list.scrollTop = list.scrollHeight;
}

/* ==================== INPUT AREA ==================== */
const input = document.getElementById('chat-input');
function sendMessageText() {
    const text = input.value.trim();
    if(text && currentPeerId) {
        if (currentPeerId === '#BROADCAST') {
            window.pywebview.api.broadcast_message(text);
        } else {
            window.pywebview.api.send_message(currentPeerId, text);
        }
        input.value = "";
    }
    input.focus();
}

input.addEventListener('keydown', (e) => {
    if(e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessageText();
    }
});
document.getElementById('btn-send').onclick = sendMessageText;

// Emoji
const emojiPicker = document.getElementById('emoji-picker');
EMOJI_LIST.forEach(e => {
    const span = document.createElement('span');
    span.className = 'emoji-item';
    span.innerText = e;
    span.onclick = () => {
        input.value += e;
        input.focus();
        emojiPicker.classList.add('hidden');
    };
    emojiPicker.appendChild(span);
});
document.getElementById('btn-emoji').onclick = () => {
    emojiPicker.classList.toggle('hidden');
};

// File Attach
document.getElementById('btn-file').onclick = async () => {
    if(!currentPeerId) {
        alert("请先在左侧选择一个聊天");
        return;
    }
    const path = await window.pywebview.api.choose_file();
    if(path) {
        if (currentPeerId === '#BROADCAST') {
            window.pywebview.api.broadcast_file(path);
        } else {
            window.pywebview.api.send_file(currentPeerId, path);
        }
        // Add local preview immediately
        const fname = path.split('/').pop() || path;
        handleIncomingMessage({
            sender_id: currentPeerId,
            alias: myAlias,
            content: `发送: ${fname}`,
            timestamp: Math.floor(Date.now()/1000),
            is_me: true,
            is_file: true,
            file_path: path,
            file_name: fname,
            is_broadcast: currentPeerId === '#BROADCAST'
        });
    }
};

/* ==================== SETTINGS ==================== */
document.getElementById('btn-open-settings').onclick = async () => {
    const cfg = await window.pywebview.api.get_config();
    document.getElementById('set-alias').value = cfg.node_alias;
    document.getElementById('set-interval').value = cfg.broadcast_interval;
    document.getElementById('set-sf').checked = cfg.enable_store_and_forward;
    document.getElementById('settings-modal').classList.remove('hidden');
};
document.getElementById('btn-close-settings').onclick = () => {
    document.getElementById('settings-modal').classList.add('hidden');
};
document.getElementById('btn-copy-fp').onclick = () => {
    const fp = document.getElementById('fingerprint-out').value;
    navigator.clipboard.writeText(fp).then(()=>alert("已复制指纹"));
};
document.getElementById('btn-save-settings').onclick = async () => {
    const alias = document.getElementById('set-alias').value;
    const interval = parseInt(document.getElementById('set-interval').value);
    const sf = document.getElementById('set-sf').checked;
    await window.pywebview.api.save_config({
        node_alias: alias,
        broadcast_interval: interval,
        enable_store_and_forward: sf
    });
    myAlias = alias;
    document.getElementById('settings-modal').classList.add('hidden');
};
