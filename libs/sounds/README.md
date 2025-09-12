# Sounds - Lucia Library

Cross-platform sound playback for Lucia, with support for WAV/MP3, volume, duration, looping, and sync/async modes.

## Features
- Play sound files (WAV, MP3, FLAC, AAC, OGG, M4A)
- Specify playback duration (milliseconds)
- Loop playback
- Set playback volume (0.0 to 1.0)
- Sync (blocking) or async (non-blocking) playback
- Automatic conversion of non-WAV formats to WAV
- Debug output for troubleshooting

## Get started

First, make sure `sounds` are installed

```bash
lym install sounds
```

Then try running

```lucia
import sounds

// Play a sound (blocking until finished)
sound := sounds.play_sound("miku.mp3", loop=false, volume=1.0, sync=true)

// Play a sound asynchronously (returns immediately)
sound := sounds.play_sound("miku.mp3", duration_ms=5000, loop=true, volume=0.5, sync=false)

// Stop a sound
sounds.stop_sound(sound)
```

## Parameters
- `path: str` - Path to the sound file
- `duration_ms: float` - Duration in milliseconds to play
- `loop: bool` - Whether to loop playback
- `volume: float` - Playback volume (0.0 to 1.0)
- `sync: bool` - If true, blocks until sound finishes; if false, returns immediately

**Warning:** If `sync` is false, you must manually wait (e.g. with `time.sleep`) until the sound finishes, otherwise playback may be cut off when your code ends.

**Note:** `duration_ms` only works in async mode (`sync=false`). In sync mode, the sound will always play to completion regardless of the duration specified.

## Native Implementation
- Windows: Uses PlaySoundA and waveOutSetVolume
- Linux/macOS: Uses ffplay/aplay/afplay
- Async/looping handled via threads on Windows

## Requirements
- Lucia runtime
- Windows: `winmm.dll` (included by default)
- Linux/macOS: ffplay/aplay/afplay installed

## License
MIT
