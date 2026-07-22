let audioCtx = null;

// Synthesized two-tone alert — no external audio file needed.
export function playWarningSound() {
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    const now = audioCtx.currentTime;

    [880, 660].forEach((freq, i) => {
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = "sine";
      osc.frequency.value = freq;

      const start = now + i * 0.16;
      gain.gain.setValueAtTime(0, start);
      gain.gain.linearRampToValueAtTime(0.18, start + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.15);

      osc.connect(gain).connect(audioCtx.destination);
      osc.start(start);
      osc.stop(start + 0.16);
    });
  } catch {
    // Web Audio unsupported or blocked — fail silently.
  }
}

export async function ensureNotificationPermission() {
  if (!("Notification" in window)) return "unsupported";
  if (Notification.permission === "default") {
    try {
      return await Notification.requestPermission();
    } catch {
      return "denied";
    }
  }
  return Notification.permission;
}

export async function notifyCriticalFindings(count, rootPath) {
  playWarningSound();

  const permission = await ensureNotificationPermission();
  if (permission !== "granted") return;

  try {
    new Notification("Security Token Janitor", {
      body: `${count} critical/high severity leak${count === 1 ? "" : "s"} found in ${rootPath}`,
      tag: "token-janitor-alert",
    });
  } catch {
    // Notification construction can throw in some environments — ignore.
  }
}
