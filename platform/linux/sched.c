#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

int sched_ctx_init(struct sched_ctx *ctx)
{
    pthread_cond_init(&ctx->cond, NULL);
    ctx->interrupted = 0; // false
    ctx->wc = 0;
    return 0;
}
int sched_ctx_destroy(struct sched_ctx *ctx)
{
    return pthread_cond_destroy(&ctx->cond);
}
int sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime)
{
    int ret;

    if (ctx->interrupted)
    {
        errno = EINTR;
        return -1;
    }
    ctx->wc++;
    // wait until pthead_cond_broadcast() will be called
    if (abstime)
    {
        // with timeout
        ret = pthread_cond_timedwait(&ctx->cond, mutex, abstime);//mutex unlocked temporary
    }
    else
    {
        ret = pthread_cond_wait(&ctx->cond, mutex);//mutex unlocked temporary
    }
    ctx->wc--;
    if (ctx->interrupted)
    {
        if (!ctx->wc)
        { // if all waiting thread wakeup, clear interrupt flag
            ctx->interrupted = 0;
        }
        errno = EINTR;
        return -1;
    }
    return ret;
}

int sched_wakeup(struct sched_ctx *ctx)
{
    return pthread_cond_broadcast(&ctx->cond);
}
int sched_interrupt(struct sched_ctx *ctx)
{
    ctx->interrupted = 1;
    return pthread_cond_broadcast(&ctx->cond);
}
