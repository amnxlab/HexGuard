/**
 * VoiceInput.tsx — Mic button with Web Speech API (webkitSpeechRecognition).
 *
 * States:
 *   idle       — microphone ready, not recording
 *   listening  — actively recording, interim results may fire
 *   error      — not-supported | no-permission | no-speech | network
 *
 * The component calls onTranscript() with the final transcript text and
 * then returns to "idle" automatically.
 *
 * Note: webkitSpeechRecognition is built into Electron's Chromium.
 * No external dependency is required.
 */

import React, { useCallback, useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Mic } from "lucide-react";

// ─── Type augmentation for webkitSpeechRecognition ───────────────────────────

declare global {
  interface Window {
    webkitSpeechRecognition?: new () => SpeechRecognitionLike;
    SpeechRecognition?: new () => SpeechRecognitionLike;
  }
}

interface SpeechRecognitionLike {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  maxAlternatives: number;
  start(): void;
  stop(): void;
  abort(): void;
  onstart: (() => void) | null;
  onend: (() => void) | null;
  onresult: ((e: SpeechRecognitionEventLike) => void) | null;
  onerror: ((e: SpeechRecognitionErrorLike) => void) | null;
}

interface SpeechRecognitionEventLike {
  resultIndex: number;
  results: SpeechRecognitionResultListLike;
}

interface SpeechRecognitionResultListLike {
  length: number;
  item(index: number): SpeechRecognitionResultLike;
  [index: number]: SpeechRecognitionResultLike;
}

interface SpeechRecognitionResultLike {
  isFinal: boolean;
  [index: number]: { transcript: string };
}

interface SpeechRecognitionErrorLike {
  error: "not-allowed" | "no-speech" | "network" | "aborted" | "audio-capture" | string;
}

// ─── Error display map ────────────────────────────────────────────────────────

const ERROR_LABELS: Record<string, string> = {
  "not-supported":  "Voice not supported in this browser",
  "not-allowed":    "Microphone permission denied",
  "no-speech":      "No speech detected",
  "network":        "Network error during transcription",
  "audio-capture":  "Microphone unavailable",
  "aborted":        "Recording aborted",
};

// ─── Hook ─────────────────────────────────────────────────────────────────────

type VoiceState = "idle" | "listening" | "error";
type VoiceError = keyof typeof ERROR_LABELS | string | null;

function useSpeechRecognition(
  onTranscript: (text: string) => void,
  onInterim?: (text: string) => void,
  /** Called when Web Speech fails with a network/permission error so the
   *  component can fall back to the offline Whisper path. */
  onFallback?: () => void,
) {
  const [state, setState]   = useState<VoiceState>("idle");
  const [error, setError]   = useState<VoiceError>(null);
  const recogRef            = useRef<SpeechRecognitionLike | null>(null);
  const activeRef           = useRef(false);
  const errorTimerRef       = useRef<ReturnType<typeof setTimeout> | null>(null);

  const isSupported =
    typeof window !== "undefined" &&
    !!(window.webkitSpeechRecognition ?? window.SpeechRecognition);

  const stop = useCallback(() => {
    activeRef.current = false;
    recogRef.current?.stop();
    setState("idle");
  }, []);

  const start = useCallback(() => {
    if (!isSupported) {
      setError("not-supported");
      setState("error");
      return;
    }
    if (activeRef.current) { stop(); return; }

    const Ctor = window.webkitSpeechRecognition ?? window.SpeechRecognition!;
    const recog = new Ctor();
    recog.continuous      = false;
    recog.interimResults  = true;
    recog.lang            = navigator.language || "en-US";
    recog.maxAlternatives = 1;

    recog.onstart = () => { setState("listening"); setError(null); };

    recog.onresult = (e) => {
      let finalText = "";
      let interimText = "";
      for (let i = e.resultIndex; i < e.results.length; i++) {
        if (e.results[i].isFinal) {
          finalText += e.results[i][0].transcript;
        } else {
          interimText += e.results[i][0].transcript;
        }
      }
      if (interimText && onInterim) onInterim(interimText);
      if (finalText.trim()) {
        if (onInterim) onInterim("");   // clear interim on commit
        onTranscript(finalText.trim());
      }
    };

    recog.onerror = (e) => {
      setError(e.error);
      setState("error");
      activeRef.current = false;
      // Auto-switch to local Whisper on network/permission errors (if fallback is wired up).
      if ((e.error === "network" || e.error === "not-allowed") && onFallback) {
        onFallback();
      }
      // Auto-dismiss error tooltip after 4 s so the button is usable again.
      if (errorTimerRef.current) clearTimeout(errorTimerRef.current);
      errorTimerRef.current = setTimeout(() => {
        setState(s => (s === "error" ? "idle" : s));
        setError(null);
      }, 4000);
    };

    recog.onend = () => {
      if (activeRef.current) {
        activeRef.current = false;
        setState("idle");
      }
    };

    recogRef.current = recog;
    activeRef.current = true;

    try {
      recog.start();
    } catch {
      setError("audio-capture");
      setState("error");
      activeRef.current = false;
    }
  }, [isSupported, onTranscript, stop]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      activeRef.current = false;
      recogRef.current?.abort();
      if (errorTimerRef.current) clearTimeout(errorTimerRef.current);
    };
  }, []);

  return { state, error, isSupported, start, stop };
}

// ─── MediaRecorder + Whisper fallback hook ────────────────────────────────────
// Used when Web Speech API is unavailable (no internet / Google STT blocked).
// Captures audio via MediaRecorder, encodes to base64, and sends to the local
// faster-whisper instance running inside the hexstrike Python server.

type WhisperState = "idle" | "recording" | "processing" | "error";

function useWhisperFallback(
  onTranscript: (text: string) => void,
  onInterim?: (text: string) => void,
) {
  const [state, setState]   = useState<WhisperState>("idle");
  const [amplitude, setAmp] = useState(0);
  const recorderRef  = useRef<MediaRecorder | null>(null);
  const chunksRef    = useRef<Blob[]>([]);
  const audioCtxRef  = useRef<AudioContext | null>(null);
  const analyserRef  = useRef<AnalyserNode | null>(null);
  const animRef      = useRef<number | null>(null);
  const streamRef    = useRef<MediaStream | null>(null);
  const activeRef    = useRef(false);

  const cleanup = useCallback(() => {
    activeRef.current = false;
    if (animRef.current) cancelAnimationFrame(animRef.current);
    if (audioCtxRef.current?.state !== "closed") void audioCtxRef.current?.close();
    streamRef.current?.getTracks().forEach(t => t.stop());
    recorderRef.current = null;
    audioCtxRef.current = null;
    analyserRef.current = null;
    streamRef.current   = null;
    chunksRef.current   = [];
    setAmp(0);
  }, []);

  const stop = useCallback(() => {
    if (recorderRef.current?.state === "recording") {
      recorderRef.current.stop();
    } else {
      cleanup();
      setState("idle");
    }
  }, [cleanup]);

  const start = useCallback(async () => {
    if (activeRef.current) { stop(); return; }
    activeRef.current = true;
    setState("recording");
    chunksRef.current = [];

    let stream: MediaStream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch {
      activeRef.current = false;
      setState("error");
      setTimeout(() => setState(s => (s === "error" ? "idle" : s)), 4000);
      return;
    }
    streamRef.current = stream;

    // Web Audio API — amplitude tracking + silence auto-stop
    const audioCtx = new AudioContext();
    audioCtxRef.current = audioCtx;
    const analyser = audioCtx.createAnalyser();
    analyserRef.current = analyser;
    analyser.fftSize = 256;
    analyser.smoothingTimeConstant = 0.8;
    audioCtx.createMediaStreamSource(stream).connect(analyser);

    const bufData = new Uint8Array(analyser.frequencyBinCount);

    // Amplitude tracking only - no silence auto-stop.
    // Recording continues until the user clicks to stop.
    const tick = () => {
      if (!activeRef.current) return;
      animRef.current = requestAnimationFrame(tick);
      analyser.getByteFrequencyData(bufData);
      const rms = Math.sqrt(bufData.reduce((s, v) => s + v * v, 0) / bufData.length) / 128;
      setAmp(Math.min(rms * 2.5, 1));
    };
    animRef.current = requestAnimationFrame(tick);

    const mimeType = MediaRecorder.isTypeSupported("audio/webm;codecs=opus")
      ? "audio/webm;codecs=opus"
      : MediaRecorder.isTypeSupported("audio/webm") ? "audio/webm" : "audio/ogg";

    const recorder = new MediaRecorder(stream, { mimeType });
    recorderRef.current = recorder;
    recorder.ondataavailable = (e) => { if (e.data.size > 0) chunksRef.current.push(e.data); };

    recorder.onstop = async () => {
      cleanup();
      const blobs = chunksRef.current;
      if (!blobs.length) { setState("idle"); return; }

      setState("processing");
      if (onInterim) onInterim("Transcribing…");

      try {
        const blob = new Blob(blobs, { type: mimeType });
        const buf  = await blob.arrayBuffer();
        let binary = "";
        new Uint8Array(buf).forEach(b => { binary += String.fromCharCode(b); });
        const b64 = btoa(binary);

        const transcript = await window.hexguard?.transcribeAudio?.(b64, mimeType.split(";")[0]);
        if (onInterim) onInterim("");
        if (transcript?.trim()) onTranscript(transcript.trim());
        setState("idle");
      } catch (err) {
        console.error("[VoiceInput/Whisper]", err);
        if (onInterim) onInterim("");
        setState("error");
        setTimeout(() => setState(s => (s === "error" ? "idle" : s)), 4000);
      }
    };

    recorder.start(200);
  }, [stop, cleanup, onTranscript, onInterim]);

  useEffect(() => () => { activeRef.current = false; cleanup(); }, [cleanup]);

  return { state, amplitude, start, stop };
}

// ─── Component ────────────────────────────────────────────────────────────────

interface VoiceInputProps {
  onTranscript: (text: string) => void;
  /** Called with partial (interim) transcript text while the user is speaking;
   *  called with an empty string when the interim is committed or cleared. */
  onInterim?: (text: string) => void;
  disabled?: boolean;
}

export default function VoiceInput({ onTranscript, onInterim, disabled = false }: VoiceInputProps) {
  // Default to Whisper mode when running in Electron (hexguard.transcribeAudio is injected
  // via preload). Web Speech requires Google’s cloud STT which is unavailable offline /
  // in a desktop app context, so it fails immediately with a “network” error.
  const [whisperMode, setWhisperMode] = useState(
    () => typeof window !== "undefined" && !!window.hexguard?.transcribeAudio,
  );
  // Ref so the Web Speech fallback callback can call whisper.start() without
  // creating a stale-closure / dependency cycle.
  const whisperStartRef = useRef<(() => Promise<void>) | null>(null);

  // Offline Whisper path (MediaRecorder → hexstrike server)
  const whisper = useWhisperFallback(onTranscript, onInterim);
  whisperStartRef.current = whisper.start;

  // Online Web Speech API path — falls back to Whisper on network/permission errors.
  // Only used when Whisper is not available (browser context without preload).
  const webSpeech = useSpeechRecognition(
    onTranscript,
    onInterim,
    () => {
      if (window.hexguard?.transcribeAudio) {
        setWhisperMode(true);
        // Auto-start Whisper so the user doesn’t need to click a second time.
        void whisperStartRef.current?.();
      }
    },
  );

  // Unified state for button styling
  const isRecording  = whisperMode && whisper.state === "recording";
  const isProcessing = whisperMode && whisper.state === "processing";
  const activeState: VoiceState =
    whisperMode
      ? (isRecording || isProcessing ? "listening" : whisper.state === "error" ? "error" : "idle")
      : webSpeech.state;

  const isSupported =
    typeof window !== "undefined" &&
    (!!window.hexguard?.transcribeAudio || !!(window.webkitSpeechRecognition ?? window.SpeechRecognition));

  const error = whisperMode ? null : webSpeech.error;

  function handleClick() {
    if (whisperMode) {
      if (isRecording) whisper.stop();
      else void whisper.start();
    } else {
      webSpeech.start();
    }
  }

  const modeLabel = whisperMode ? " (offline)" : "";
  const title =
    !isSupported               ? "Voice input not supported" :
    activeState === "error" && error ? (ERROR_LABELS[error] ?? `Error: ${error}`) :
    isProcessing               ? "Transcribing…" :
    isRecording                ? "Recording… click to stop" :
    activeState === "listening" ? "Listening… click to cancel" :
    `Voice input${modeLabel}`;

  return (
    <div style={{ position: "relative", display: "flex", alignItems: "center", gap: 4 }}>
      {/* Waveform amplitude bars — visible in MediaRecorder / Whisper mode while recording */}
      {isRecording && (
        <div className="voice-waveform" aria-hidden="true">
          {[0.3, 0.6, 1, 0.6, 0.3].map((scale, i) => (
            <span
              key={i}
              className="voice-waveform-bar"
              style={{ transform: `scaleY(${0.2 + whisper.amplitude * scale})` }}
            />
          ))}
        </div>
      )}

      <motion.button
        className={`composer-icon-btn voice-btn ${activeState}`}
        title={title}
        disabled={disabled || !isSupported}
        onClick={handleClick}
        aria-label={title}
        aria-pressed={activeState === "listening"}
        whileTap={{ scale: 0.88 }}
        style={{
          color: activeState === "listening" ? "var(--accent)"
               : activeState === "error"    ? "var(--red)"
               : undefined,
          position: "relative",
        }}
      >
        {/* Radial pulse rings when listening via Web Speech */}
        <AnimatePresence>
          {activeState === "listening" && !isRecording && [0, 1, 2].map(i => (
            <motion.span
              key={i}
              className="voice-pulse-ring"
              initial={{ scale: 1, opacity: 0.7 }}
              animate={{ scale: 2.4, opacity: 0 }}
              transition={{ duration: 1.8, delay: i * 0.6, repeat: Infinity, ease: "easeOut" }}
            />
          ))}
        </AnimatePresence>
        <Mic size={14} strokeWidth={1.7} />
      </motion.button>

      {/* Error tooltip */}
      <AnimatePresence>
      {activeState === "error" && error && (
        <motion.div
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 4 }}
          transition={{ duration: 0.15 }}
          style={{
            position: "absolute",
            bottom: "calc(100% + 6px)",
            right: 0,
            background: "var(--bg3)",
            border: "1px solid var(--red)",
            borderRadius: 7,
            padding: "4px 10px",
            fontSize: "0.72rem",
            color: "var(--red)",
            whiteSpace: "nowrap",
            zIndex: 100,
          }}
        >
          {ERROR_LABELS[error] ?? `Voice error: ${error}`}
        </motion.div>
      )}
      </AnimatePresence>
    </div>
  );
}
