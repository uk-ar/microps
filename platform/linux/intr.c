#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "net.h"

struct irq_entry
{
    struct irq_entry *next;
    unsigned int irq;
    int (*handler)(unsigned int irq, void *dev);
    int flags;
    char name[16];
    void *dev;
};

/* NOTE: if you want to add/delete the entries after intr_run(),
you need to protect these lines with a mutex */
static struct irq_entry *irqs;

static sigset_t sigmask;

static pthread_t tid;
static pthread_barrier_t barrier;

int intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *dev),
                     int flags, const char *name, void *dev)
{
    struct irq_entry *entry;
    debugf("irq=%u,flags=%d,name=%s", irq, flags, name);
    for (entry = irqs; entry; entry = entry->next)
    {
        if (entry->irq == irq)
        {
            // chack if both allowed sharead
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED)
            {
                errorf("conflicts with already registered IRQs");
                return -1;
            }
        }
    }

    entry = memory_alloc(sizeof(*entry));
    if (!entry)
    {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->dev = dev;
    entry->next = irqs;
    irqs = entry;
    sigaddset(&sigmask, irq);
    debugf("registered:irq=%u,name=%s", irq, name);
    return 0;
}

int intr_raise_irq(unsigned int irq)
{
    // raise signal to signal handing thread(intr_thread)
    return pthread_kill(tid, (int)irq);
}

static int intr_timer_setup(struct itimerspec *interval)
{
    timer_t id;

    if (timer_create(CLOCK_REALTIME, NULL, &id) == -1)
    {
        errorf("timer_create:%s", strerror(errno));
        return -1;
    }
    if (timer_settime(id, 0, interval, NULL) == -1)
    {
        errorf("timer_settime:%s", strerror(errno));
        return -1;
    }
    return 0;
}

// bottom half of signal handling
static void *intr_thread(void *arg)
{
    int terminate = 0, sig, err;
    struct irq_entry *entry;
    const struct timespec ts = {0, 1000000}; /* 1 ms */
    struct itimerspec interval = {ts, ts};

    debugf("start...");
    pthread_barrier_wait(&barrier);
    if (intr_timer_setup(&interval) == -1)
    {
        errorf("intr_timer_setup() failure");
        return NULL;
    }
    while (!terminate)
    {
        err = sigwait(&sigmask, &sig);
        if (err)
        {
            errorf("sigwait() %s", strerror(err));
            break;
        }
        switch (sig)
        {
        case SIGHUP:
            terminate = 1;
            break;
        case SIGUSR1:
            // call bottom half
            net_softirq_handler();
            break;
        case SIGUSR2:
            net_event_handler();
            break;
        case SIGALRM:
            net_timer_handler();
            break;
        default:
            for (entry = irqs; entry; entry = entry->next)
            {
                if (entry->irq == (unsigned int)sig)
                {
                    // call intrupt handler
                    debugf("irq=%d,name=%s", entry->irq, entry->name);
                    entry->handler(entry->irq, entry->dev);
                }
            }
            break;
        }
    }
    debugf("terminated");
    return NULL;
}

int intr_run(void)
{
    int err;

    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err)
    {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err)
    {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }
    pthread_barrier_wait(&barrier);
    return 0;
}

void intr_shutdown(void)
{
    if (pthread_equal(tid, pthread_self()) != 0)
    {
        /* signal handling thread not created */
        return;
    }
    pthread_kill(tid, SIGHUP); // stop signal handling thread
    pthread_join(tid, NULL);
}

int intr_init(void)
{
    tid = pthread_self();
    pthread_barrier_init(&barrier, NULL, 2);
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGHUP);  // for the sake of stopping signal handling thread
    sigaddset(&sigmask, SIGUSR1); // for the sake of handling protocol bottom half
    sigaddset(&sigmask, SIGUSR2); // for event handling
    sigaddset(&sigmask, SIGALRM); // when timer event occur raise SIGALRM
    return 0;
}