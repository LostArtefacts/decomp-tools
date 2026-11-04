/* Stands in for c2.exe (cl /B2): keeps a copy of the intermediate files
   cl hands the back end, and its flags (MSC_CMD_FLAGS), in the directory
   C2KEEP, then runs the real back end, C2REAL. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>

int main(void)
{
    char *keep = getenv("C2KEEP");
    char *flags = getenv("MSC_CMD_FLAGS");
    char il[MAX_PATH], pattern[MAX_PATH], src[MAX_PATH], dst[MAX_PATH], *p, *slash;
    WIN32_FIND_DATA fd;
    HANDLE h;
    FILE *f;
    int n = 0;
    if (keep && flags && (p = strstr(flags, "-il ")) != NULL) {
        p += 4;
        while (p[n] && p[n] != ' ')
            n++;
        sprintf(il, "%.*s", n, p);
        sprintf(pattern, "%s*", il);
        slash = strrchr(il, '\\');
        h = FindFirstFile(pattern, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                sprintf(src, "%.*s%s", slash ? (int)(slash - il + 1) : 0, il, fd.cFileName);
                sprintf(dst, "%s\\%s", keep, fd.cFileName);
                CopyFile(src, dst, FALSE);
            } while (FindNextFile(h, &fd));
            FindClose(h);
        }
        sprintf(dst, "%s\\flags.txt", keep);
        f = fopen(dst, "w");
        if (f) {
            fprintf(f, "%s\n", flags);
            fclose(f);
        }
    }
    return _spawnl(_P_WAIT, getenv("C2REAL"), "c2.exe", NULL);
}
