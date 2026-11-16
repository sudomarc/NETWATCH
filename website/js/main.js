/* ==========================================================================
   NETWATCH NG — showcase site interactions
   Scroll reveals (IntersectionObserver), character-by-character TUI typing,
   demonstration tabs, command copy, navigation.
   Respects prefers-reduced-motion.
   ========================================================================== */
(function () {
  "use strict";

  var REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- Navbar: shadow on scroll ---------- */
  var header = document.querySelector(".nav-header");
  var onScroll = function () {
    header.classList.toggle("is-scrolled", window.scrollY > 8);
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  /* ---------- Mobile menu ---------- */
  var burger = document.getElementById("navBurger");
  var mobileNav = document.getElementById("navMainMobile");
  if (burger && mobileNav) {
    burger.addEventListener("click", function () {
      var open = mobileNav.classList.toggle("is-open");
      burger.setAttribute("aria-expanded", open ? "true" : "false");
      burger.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    });
    mobileNav.addEventListener("click", function (e) {
      if (e.target.tagName === "A") {
        mobileNav.classList.remove("is-open");
        burger.setAttribute("aria-expanded", "false");
      }
    });
  }

  /* ---------- Scroll reveals ---------- */
  var revealEls = document.querySelectorAll(".reveal");
  if (REDUCED || !("IntersectionObserver" in window)) {
    revealEls.forEach(function (el) { el.classList.add("is-visible"); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -40px 0px" });
    revealEls.forEach(function (el) { io.observe(el); });
  }

  /* ---------- Command copy ---------- */
  document.querySelectorAll(".copy-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var target = document.getElementById(btn.getAttribute("data-copy-target"));
      if (!target) return;
      var text = target.textContent.replace(/\s*\n\s*/g, "\n").trim();
      var done = function () {
        btn.classList.add("is-copied");
        setTimeout(function () { btn.classList.remove("is-copied"); }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); } catch (e) { /* noop */ }
        document.body.removeChild(ta);
        done();
      }
    });
  });

  /* ---------- FAQ: one panel open at a time ---------- */
  var faqItems = document.querySelectorAll(".faq-item");
  faqItems.forEach(function (item) {
    item.addEventListener("toggle", function () {
      if (!item.open) return;
      faqItems.forEach(function (other) {
        if (other !== item && other.open) other.open = false;
      });
    });
  });

  /* ---------- Generic typer ---------- */
  function typeInto(el, segments, opts) {
    // segments: [{ text, cls, pause }] ; type line by line, character by character.
    var options = Object.assign({ cps: 90, linePause: 260, done: null }, opts || {});
    el.textContent = "";
    if (REDUCED) {
      segments.forEach(function (seg) {
        var span = document.createElement("span");
        if (seg.cls) span.className = seg.cls;
        span.textContent = seg.text;
        el.appendChild(span);
      });
      if (options.done) options.done();
      return;
    }
    var si = 0, ci = 0;
    var current = null;
    function step() {
      if (si >= segments.length) {
        if (options.done) options.done();
        return;
      }
      var seg = segments[si];
      if (ci === 0) {
        current = document.createElement("span");
        if (seg.cls) current.className = seg.cls;
        el.appendChild(current);
      }
      if (ci < seg.text.length) {
        var burst = Math.max(1, Math.round(options.cps / 60));
        current.textContent += seg.text.slice(ci, ci + burst);
        ci += burst;
        setTimeout(step, Math.round(1000 / options.cps));
      } else {
        si += 1; ci = 0;
        setTimeout(step, seg.pause != null ? seg.pause : options.linePause);
      }
    }
    step();
  }

  /* ---------- Hero TUI: Dashboard lines ---------- */
  var tuiLines = document.getElementById("tuiLines");
  if (tuiLines) {
    var heroScript = [
      { text: "NETWORK IDENTITY", cls: "tl-head" },
      { text: "  Host      debian-noc", cls: "" },
      { text: "  Ifaces    eth0, wlan0, wg0", cls: "tl-cyan" },
      { text: "  Gateway   192.168.1.1  REACHABLE", cls: "" },
      { text: "", pause: 120 },
      { text: "OPERATIONAL COUNTS", cls: "tl-head" },
      { text: "  Devices   12 known · 3 new", cls: "" },
      { text: "  Wi-Fi     wlan0 managed · 8 APs seen", cls: "tl-cyan" },
      { text: "  Firewall  NETWATCH chain OWNED", cls: "tl-green" },
      { text: "  Traffic   eth0 egress 20000 kbit/s", cls: "tl-amber" },
      { text: "", pause: 120 },
      { text: "RECENT ACTIVITY", cls: "tl-head" },
      { text: "  14:02  Diagnostics  ping_gateway  ok", cls: "tl-dim" },
      { text: "  14:01  Devices       active_scan   ok", cls: "tl-dim" },
      { text: "  13:58  Firewall      block        ok", cls: "tl-dim" },
      { text: "STATUS: READY", cls: "tl-green", pause: 900 }
    ];
    var startHero = function () {
      if (tuiLines.dataset.started) return;
      tuiLines.dataset.started = "1";
      typeInto(tuiLines, heroScript, { cps: 130, linePause: 200 });
    };
    if (REDUCED || !("IntersectionObserver" in window)) startHero();
    else {
      var heroIO = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) { startHero(); heroIO.disconnect(); }
        });
      }, { threshold: 0.3 });
      heroIO.observe(tuiLines);
    }
  }

  /* ---------- Tabbed demonstration ---------- */
  var DEMOS = {
    discovery: {
      title: "netwatch-ng — Devices",
      lines: [
        { text: "$ n: Nmap discovery (authorized target only)", cls: "tl-dim" },
        { text: "Active Nmap discovery in progress for 192.168.1.0/24..." },
        { text: "IP              MAC                STATE     IDENTITY" },
        { text: "192.168.1.1     b8:27:eb:2a:1f:04  READY     gateway (OUI Raspberry)" },
        { text: "192.168.1.17    d8:3a:dd:41:0c:99  READY     raspberry — evidence: arp+oui", cls: "tl-cyan" },
        { text: "192.168.1.42    a4:83:e7:5e:d2:10  BLOCK     printer — confidence: medium", cls: "tl-red" },
        { text: "Active discovery complete: 12 device(s)." },
        { text: "e: export json/csv · v: service scan (single host)" , cls: "tl-dim" }
      ]
    },
    wifi: {
      title: "netwatch-ng — Wi-Fi Intelligence",
      lines: [
        { text: "$ s: access-point survey", cls: "tl-dim" },
        { text: "Wi-Fi survey in progress..." },
        { text: "SSID             BSSID              CH   SECURITY       SIGNAL" },
        { text: "noc-corp         b8:27:eb:2a:1f:04  06   WPA2           -42 dBm", cls: "tl-cyan" },
        { text: "guest-wifi       b8:27:eb:2a:1f:05  11   WPA2           -61 dBm" },
        { text: "iot-lab          9c:53:22:88:17:e0  01   WEP            -74 dBm", cls: "tl-amber" },
        { text: "Announced security = indicator, not verification.", cls: "tl-dim" },
        { text: "m: monitor mode (explicit confirmation; default route protected)", cls: "tl-dim" }
      ]
    },
    firewall: {
      title: "netwatch-ng — Firewall",
      lines: [
        { text: "$ b: block an IPv4/IPv6", cls: "tl-dim" },
        { text: "Target: 192.168.1.42", cls: "tl-cyan" },
        { text: "Block 192.168.1.42 on the forwarding path? y/N" },
        { text: "Scope: FORWARD chain · NETWATCH-owned rules", cls: "tl-amber" },
        { text: "Block applied: 192.168.1.42" },
        { text: "IPv4: NETWATCH_BLOCK chain OWNED · rollback ready", cls: "tl-dim" },
        { text: "IPv6: ip6tables, gateway never targeted", cls: "tl-dim" }
      ]
    },
    diagnostic: {
      title: "netwatch-ng — Network Diagnostics",
      lines: [
        { text: "$ p: ping gateway", cls: "tl-dim" },
        { text: "Pinging configured default gateway..." },
        { text: "PING 192.168.1.1 : seq=1 ttl=64 time=1.42 ms" },
        { text: "PING 192.168.1.1 : seq=2 ttl=64 time=1.31 ms" },
        { text: "Result: gateway reachable — average latency 1.36 ms", cls: "tl-green" },
        { text: "$ d: DNS resolution · $ t: trace route", cls: "tl-dim" },
        { text: "Activity log: timestamped event, success status.", cls: "tl-dim" }
      ]
    },
    traffic: {
      title: "netwatch-ng — Traffic Manager",
      lines: [
        { text: "$ l: set a rate limit", cls: "tl-dim" },
        { text: "Interface: eth0 · Rate: 20000 kbit/s · Direction: egress", cls: "tl-cyan" },
        { text: "egress: packet policing applied on eth0 at 20000 kbit/s." },
        { text: "Above rate: packets dropped (policing).", cls: "tl-amber" },
        { text: "Root qdisc is never replaced (no HTB).", cls: "tl-dim" },
        { text: "c: remove NETWATCH policing (confirmation required)", cls: "tl-dim" }
      ]
    }
  };

  var demoScreen = document.getElementById("demoScreen");
  var demoTitle = document.getElementById("demoTitle");
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".demo-tab"));
  var captions = Array.prototype.slice.call(document.querySelectorAll(".demo-caption"));
  var demoStarted = false;
  var demoToken = 0;

  function playDemo(key) {
    var demo = DEMOS[key];
    if (!demo || !demoScreen) return;
    var token = ++demoToken;
    if (demoTitle) demoTitle.textContent = demo.title;
    typeInto(demoScreen, demo.lines, {
      cps: 260,
      linePause: 150,
      done: function () { /* remains displayed */ }
    });
    // guard: if another tab was activated during typing
    if (token !== demoToken) demoToken = token;
  }

  function activateTab(tab) {
    var key = tab.id.replace("tab-", "");
    tabs.forEach(function (t) {
      var active = t === tab;
      t.classList.toggle("is-active", active);
      t.setAttribute("aria-selected", active ? "true" : "false");
    });
    captions.forEach(function (c) {
      var show = c.id === "panel-" + key;
      c.hidden = !show;
    });
    playDemo(key);
  }

  if (tabs.length && demoScreen) {
    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () { activateTab(tab); });
    });
    // play on first entry into viewport
    if (REDUCED || !("IntersectionObserver" in window)) {
      demoStarted = true;
      playDemo("discovery");
    } else {
      var demoIO = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting && !demoStarted) {
            demoStarted = true;
            playDemo("discovery");
            demoIO.disconnect();
          }
        });
      }, { threshold: 0.25 });
      demoIO.observe(demoScreen);
    }
  }
})();
