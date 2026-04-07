#include "../inc/cpu_policy.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

static int write_file_str(const char *path, const char *s) {
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    int rc = fputs(s, f);
    fclose(f);
    return (rc < 0) ? -1 : 0;
}

static int read_file_str(const char *path, char *buf, size_t bufsz) {
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(buf, (int)bufsz, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    size_t n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';
    return 0;
}

static void mask_hex_for_cpu(int cpu, char *out, size_t outsz) {
    if (!out || outsz == 0)
        return;
    if (cpu < 0) {
        snprintf(out, outsz, "0");
        return;
    }
    unsigned long long mask = 1ULL << (unsigned int)cpu;
    snprintf(out, outsz, "%llx", mask);
}

static int if_irq_cpu(const struct app_config *cfg, const char *line) {
    if (!cfg || !line)
        return -2;
    for (int i = 0; i < cfg->local_count; i++) {
        const struct local_config *L = &cfg->locals[i];
        if (L->ifname[0] && strstr(line, L->ifname))
            return L->irq_cpu;
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        const struct wan_config *W = &cfg->wans[i];
        if (W->ifname[0] && strstr(line, W->ifname))
            return W->irq_cpu;
    }
    return -2;
}

int cpu_policy_apply(const struct app_config *cfg, struct cpu_policy_state *st) {
    if (!st)
        return -1;
    memset(st, 0, sizeof(*st));
    if (!cfg || !cfg->cpu_policy.enabled)
        return 0;

    st->enabled = 1;

    const char *bdir = cfg->cpu_policy.backup_dir[0] ? cfg->cpu_policy.backup_dir : "/root/irq-affinity-backup";
    (void)mkdir(bdir, 0700);

    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    char ts[64];
    strftime(ts, sizeof(ts), "%F_%H%M%S", &tmv);
    snprintf(st->backup_file, sizeof(st->backup_file), "%s/irq_affinity_%s.txt", bdir, ts);

    FILE *fin = fopen("/proc/interrupts", "r");
    if (!fin) {
        fprintf(stderr, "[cpu-policy] open /proc/interrupts failed: %s\n", strerror(errno));
        return -1;
    }
    FILE *fbk = fopen(st->backup_file, "w");
    if (!fbk) {
        fprintf(stderr, "[cpu-policy] open backup file failed: %s (%s)\n", st->backup_file, strerror(errno));
        fclose(fin);
        return -1;
    }

    fprintf(fbk, "# time=%s enabled=1 default_irq_cpu=%d\n", ts, cfg->cpu_policy.default_irq_cpu);

    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, fin) > 0) {
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p < '0' || *p > '9')
            continue;
        char *colon = strchr(p, ':');
        if (!colon)
            continue;
        *colon = '\0';
        int irq = atoi(p);
        *colon = ':';

        int cpu = if_irq_cpu(cfg, line);
        if (cpu == -2)
            continue; /* not our iface */
        if (cpu < -1)
            continue;
        if (cpu == -1)
            continue; /* explicitly don't touch */

        char irq_path[128];
        snprintf(irq_path, sizeof(irq_path), "/proc/irq/%d/smp_affinity", irq);

        char old_mask[128] = {0};
        if (read_file_str(irq_path, old_mask, sizeof(old_mask)) != 0)
            continue;
        fprintf(fbk, "%d %s\n", irq, old_mask);

        char new_mask[32];
        mask_hex_for_cpu(cpu, new_mask, sizeof(new_mask));
        if (write_file_str(irq_path, new_mask) != 0) {
            fprintf(stderr, "[cpu-policy] set %s=%s failed: %s\n", irq_path, new_mask, strerror(errno));
        }
    }
    free(line);
    fclose(fin);
    fclose(fbk);

    fprintf(stderr, "[cpu-policy] enabled; backup=%s\n", st->backup_file);
    return 0;
}

int cpu_policy_restore(const struct cpu_policy_state *st) {
    if (!st || !st->enabled)
        return 0;
    if (st->backup_file[0] == '\0')
        return 0;

    FILE *f = fopen(st->backup_file, "r");
    if (!f) {
        fprintf(stderr, "[cpu-policy] restore: can't open backup %s: %s\n", st->backup_file, strerror(errno));
        return -1;
    }

    char buf[256];
    while (fgets(buf, sizeof(buf), f)) {
        if (buf[0] == '#')
            continue;
        int irq = -1;
        char mask[128];
        if (sscanf(buf, "%d %127s", &irq, mask) != 2)
            continue;
        if (irq < 0)
            continue;
        char irq_path[128];
        snprintf(irq_path, sizeof(irq_path), "/proc/irq/%d/smp_affinity", irq);
        (void)write_file_str(irq_path, mask);
    }
    fclose(f);
    fprintf(stderr, "[cpu-policy] disabled; restored from %s\n", st->backup_file);
    return 0;
}

