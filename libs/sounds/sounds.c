// sounds.c - Native sound playback implementation for Lucia
// Cross-platform stub (Windows/Linux/macOS)

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#ifdef _WIN32
#define SOUNDS_EXPORT __declspec(dllexport)
#else
#define SOUNDS_EXPORT __attribute__((visibility("default")))
#endif

#ifdef _WIN32
#include <windows.h>
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")

struct AsyncParams
{
    char path[256];
    float duration_ms;
    bool loop;
    bool debug;
};
static DWORD WINAPI async_play_thread(LPVOID arg)
{
    struct AsyncParams *p = (struct AsyncParams *)arg;
    if (p->loop)
    {
        while (p->loop)
        {
            PlaySoundA(p->path, NULL, SND_FILENAME | SND_SYNC);
            if (p->debug)
                printf("[sounds] Looping sound: %s\n", p->path);
        }
    }
    else
    {
        PlaySoundA(p->path, NULL, SND_FILENAME | SND_ASYNC);
        if (p->duration_ms > 0)
        {
            Sleep((DWORD)p->duration_ms);
            PlaySoundA(NULL, NULL, 0);
        }
    }
    free(p);
    return 0;
}
#include <windows.h>
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")
#endif

struct SoundId
{
    int id;
    char path[256];
    float duration_ms;
    bool loop;
    bool playing;
};

#define MAX_SOUNDS 64
static struct SoundId sound_registry[MAX_SOUNDS];
static int next_id = 1;
SOUNDS_EXPORT int play_sound(const char *path, float duration_ms, bool loop, float volume, bool sync, bool debug)
{
    int id = next_id++;
    if (id >= MAX_SOUNDS)
        return -1;
    struct SoundId *s = &sound_registry[id];
    s->id = id;
    strncpy(s->path, path, sizeof(s->path) - 1);
    s->duration_ms = duration_ms;
    s->loop = loop;
    s->playing = true;

    if (debug)
        printf("[sounds] play_sound called: %s, duration: %f, loop: %d, volume: %f, sync: %d\n", path, duration_ms, loop, volume, sync);

#ifdef _WIN32
    char win_path[256];
    if (strncmp(path, "\\\\?\\", 4) == 0)
    {
        strncpy(win_path, path + 4, sizeof(win_path) - 1);
        win_path[sizeof(win_path) - 1] = '\0';
    }
    else
    {
        strncpy(win_path, path, sizeof(win_path) - 1);
        win_path[sizeof(win_path) - 1] = '\0';
    }
    DWORD vol = (DWORD)(volume * 0xFFFF);
    waveOutSetVolume(0, vol | (vol << 16));
    UINT flags = SND_FILENAME;
    BOOL ok;
    if (sync)
    {
        flags |= SND_SYNC;
        if (loop)
        {
            do
            {
                if (debug)
                    printf("[sounds] Looping sound (sync): %s\n", win_path);
                ok = PlaySoundA(win_path, NULL, flags);
                if (debug)
                    printf("[sounds] PlaySoundA returned %d\n", ok);
            } while (loop);
        }
        else
        {
            if (debug)
                printf("[sounds] PlaySoundA('%s', SND_SYNC)\n", win_path);
            ok = PlaySoundA(win_path, NULL, flags);
            if (debug)
                printf("[sounds] PlaySoundA returned %d\n", ok);
        }
    }
    else
    {
        flags |= SND_ASYNC;
        if (debug)
            printf("[sounds] PlaySoundA('%s', SND_ASYNC)\n", win_path);
        ok = PlaySoundA(win_path, NULL, flags);
        if (debug)
            printf("[sounds] PlaySoundA returned %d\n", ok);
        if (duration_ms > 0 || loop)
        {
            DWORD thread_id;
            struct AsyncParams *params = malloc(sizeof(struct AsyncParams));
            strncpy(params->path, win_path, 255);
            params->path[255] = '\0';
            params->duration_ms = duration_ms;
            params->loop = loop;
            params->debug = debug;
            HANDLE hThread = CreateThread(NULL, 0, async_play_thread, params, 0, &thread_id);
            CloseHandle(hThread);
        }
    }
    if (!ok)
    {
        if (debug)
            fprintf(stderr, "[sounds] ERROR: PlaySoundA failed for '%s'\n", win_path);
        return -1;
    }
    s->playing = !duration_ms || (ok && flags & SND_ASYNC);
#elif defined(__linux__)
    pid_t pid = fork();
    if (pid == 0)
    {
        if (strstr(path, ".mp3"))
        {
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "ffplay -nodisp -autoexit -volume %d '%s'", (int)(volume * 100), path);
            execlp("sh", "sh", "-c", cmd, NULL);
        }
        else
        {
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "aplay '%s'", path);
            execlp("sh", "sh", "-c", cmd, NULL);
        }
        exit(1);
    }
    s->id = pid;
    if (duration_ms > 0)
    {
        usleep((useconds_t)(duration_ms * 1000));
        kill(pid, SIGKILL);
        s->playing = false;
    }
#elif defined(__APPLE__)
    pid_t pid = fork();
    if (pid == 0)
    {
        if (strstr(path, ".mp3"))
        {
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "ffplay -nodisp -autoexit -volume %d '%s'", (int)(volume * 100), path);
            execlp("sh", "sh", "-c", cmd, NULL);
        }
        else
        {
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "afplay '%s'", path);
            execlp("sh", "sh", "-c", cmd, NULL);
        }
        exit(1);
    }
    s->id = pid;
    if (duration_ms > 0)
    {
        usleep((useconds_t)(duration_ms * 1000));
        kill(pid, SIGKILL);
        s->playing = false;
    }
#endif
    return id;
}

SOUNDS_EXPORT void stop_sound(int id)
{
    if (id <= 0 || id >= MAX_SOUNDS)
        return;
    struct SoundId *s = &sound_registry[id];
    if (!s->playing)
        return;

#ifdef _WIN32
    PlaySoundA(NULL, NULL, 0);
#elif defined(__linux__)
    kill(s->id, SIGKILL);
#elif defined(__APPLE__)
    kill(s->id, SIGKILL);
#endif
    s->playing = false;
}

SOUNDS_EXPORT struct SoundId *get_playing_sounds(int *count)
{
    static struct SoundId results[MAX_SOUNDS];
    int n = 0;
    for (int i = 1; i < next_id; ++i)
    {
        if (sound_registry[i].playing)
        {
            results[n++] = sound_registry[i];
        }
    }
    *count = n;
    return results;
}
