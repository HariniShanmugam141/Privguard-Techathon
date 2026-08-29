import glob, re

html_header_right = '''<div class="flex items-center gap-3">
    <button onclick="toggleTheme()" class="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-lg text-sm font-medium hover:bg-slate-50 shadow-sm transition-colors dark-btn">
        <i class="fa-regular fa-sun" id="theme-icon"></i> <span id="theme-text">Light</span>
    </button>
    <div style="position:relative;">
        <button onclick="toggleGlobalNotif()" class="relative p-2 bg-white border border-slate-200 rounded-lg text-slate-600 hover:bg-slate-50 w-10 h-10 flex items-center justify-center shadow-sm transition-colors dark-btn">
            <i class="fa-regular fa-bell"></i>
            <span id="g-notif-badge" style="display:none;" class="absolute top-1 right-1 w-2.5 h-2.5 bg-red-500 rounded-full border-2 border-white"></span>
        </button>
        <div id="g-notif-panel" style="display:none; position:absolute; top:calc(100% + 8px); right:0; width:280px; background:white; border:1px solid #e2e8f0; border-radius:12px; box-shadow:0 10px 25px rgba(0,0,0,.1); z-index:999; text-align:left;">
            <div style="padding:10px 14px;font-size:13px;font-weight:700;color:#374151;border-bottom:1px solid #f1f5f9;">Notifications</div>
            <div id="g-notif-list" style="padding:6px 0;font-size:13px;color:#64748b;max-height:300px;overflow-y:auto;background:white;">
                <div style="padding:12px;text-align:center;"><i class="fa-solid fa-spinner fa-spin"></i></div>
            </div>
        </div>
    </div>
    <button onclick="exportGlobalCSV()" class="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 shadow-sm transition-colors">
        <i class="fa-solid fa-download"></i> Export Report
    </button>
</div>'''

js_script = '''
<style>
html.dark-mode { filter: invert(1) hue-rotate(180deg); background-color: #000; }
html.dark-mode img, html.dark-mode canvas, html.dark-mode video, html.dark-mode .gradient-bg { filter: invert(1) hue-rotate(180deg); }
html.dark-mode .dark-btn { border-color: #d1d5db; }
</style>
<script>
(function(){
    const isDark = localStorage.getItem('theme') === 'dark';
    if(isDark) document.documentElement.classList.add('dark-mode');
    window.toggleTheme = function() {
        const isNowDark = document.documentElement.classList.toggle('dark-mode');
        localStorage.setItem('theme', isNowDark ? 'dark' : 'light');
        updateThemeUI(isNowDark);
    };
    function updateThemeUI(dark) {
        const icn = document.getElementById('theme-icon');
        const txt = document.getElementById('theme-text');
        if(icn && txt) {
            icn.className = dark ? "fa-regular fa-moon" : "fa-regular fa-sun";
            txt.textContent = dark ? "Dark" : "Light";
        }
    }
    document.addEventListener("DOMContentLoaded", () => updateThemeUI(document.documentElement.classList.contains('dark-mode')));
    window.toggleGlobalNotif = function() {
        const panel = document.getElementById('g-notif-panel');
        if(!panel) return;
        const open = panel.style.display === 'block';
        document.querySelectorAll('.dd-panel, [id^="g-notif-panel"], [id^="notif-panel"]').forEach(el => {
            if(el.style) el.style.display = 'none';
            if(el.classList) el.classList.remove('open');
        });
        if(!open) {
            panel.style.display = 'block';
            fetchNotifs();
        }
    };
    async function fetchNotifs() {
        try {
            const [stats, verify] = await Promise.all([
                fetch("/history/stats").then(r=>r.json()),
                fetch("/ledger/verify",{method:"POST"}).then(r=>r.json())
            ]);
            const items = [];
            if(stats.total_documents>0) items.push({i:"fa-shield-check",c:"#10b981",t:stats.total_documents+" documents protected"});
            if(stats.viewed_this_month>0) items.push({i:"fa-eye",c:"#6366f1",t:stats.viewed_this_month+" records viewed"});
            if(stats.deleted_this_month>0) items.push({i:"fa-trash-can",c:"#ef4444",t:stats.deleted_this_month+" records deleted"});
            items.push({i:"fa-shield",c:verify.is_valid?"#10b981":"#ef4444",t:verify.is_valid?"Audit chain verified":"Chain integrity issue!"});
            const list = document.getElementById('g-notif-list');
            if(list) list.innerHTML = items.map(i=>"<div style='display:flex;align-items:center;gap:10px;padding:8px 14px;border-bottom:1px solid #f8fafc;'><i class='fa-solid "+i.i+"' style='color:"+i.c+";font-size:14px;width:16px;'></i><span style='color:#333;font-weight:500;'>"+i.t+"</span></div>").join("");
            const badge = document.getElementById('g-notif-badge');
            if(badge) badge.style.display = items.length > 0 ? 'block' : 'none';
        } catch(e) {}
    }
    setTimeout(fetchNotifs, 1000);
    window.exportGlobalCSV = function() {
        const a = document.createElement("a");
        a.href = "/history/export/csv";
        a.download = "privguard_report.csv";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    };
    document.addEventListener("click", e => {
        if(!e.target.closest("[onclick*='toggleGlobalNotif']") && !e.target.closest("#g-notif-panel")) {
            const p = document.getElementById('g-notif-panel');
            if(p) p.style.display = 'none';
        }
    });
})();
</script>
</body>
'''

for f in glob.glob('*.html'):
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    
    if '<!-- GLOBAL HEADER FUNCTIONALITY -->' not in content:
        content = content.replace('</body>', js_script + '\n<!-- GLOBAL HEADER FUNCTIONALITY -->')
    
    if f == 'index.html':
        content = re.sub(r'<div style="display:flex;align-items:center;gap:12px;">[\s\S]*?</a>\s*</div>\s*</div>\s*<!-- CONTENT AREA -->', 
            html_header_right + '\n    </div>\n  <!-- CONTENT AREA -->', content)
    else:
        # For other files, replace the LAST div with class "flex items-center gap-3" inside the <header> tag
        header_match = re.search(r'<header[^>]*>([\s\S]*?)</header>', content)
        if header_match:
            header_full = header_match.group(0)
            inner_header = header_match.group(1)
            # find last occurrence of '<div class="flex items-center gap-3">'
            idx = inner_header.rfind('<div class="flex items-center gap-3">')
            if idx != -1:
                # The substring from idx to the end of inner_header is the right side block.
                # We replace it with our html_header_right
                new_inner = inner_header[:idx] + html_header_right + '\n    '
                new_header = header_full.replace(inner_header, new_inner)
                content = content.replace(header_full, new_header)

    with open(f, 'w', encoding='utf-8') as file:
        file.write(content)
    print(f"Updated {f}")
