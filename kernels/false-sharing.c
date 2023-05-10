//This kernel creates 8 threads that write different variables in the same cache line creating false sharing
//Usage: ./false_sharing <num-iterations>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

long n;

void *worker_thread(void *arg)
{
        struct timeval stop, start;
        gettimeofday(&start, NULL);

        long* counter_to_inc = (long*)arg;

        for(int i = 0; i < n; i++){
                (*counter_to_inc)++;
        }
        printf("counter = %ld\n",*counter_to_inc);

        gettimeofday(&stop, NULL);
        printf("took %lu us\n", (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);

        pthread_exit(NULL);
}


struct Counter{
        long count0;
        long count1;
        long count2;
        long count3;
        long count4;
        long count5;
        long count6;
        long count7;
        };

int main(int argc, char *argv[])
{
        if (argc<2) {
        printf("%s: missing <num-iterations> arg!\n", argv[0]);
        exit(-1);
        }

        struct Counter counter __attribute__((aligned(64))); //Expected to occupy 1 cache line
        struct Counter *counter_p;
        n = atol(argv[1]);

        counter.count0 = 0;
        counter.count1 = 1;
        counter.count2 = 2;
        counter.count3 = 3;
        counter.count4 = 4;
        counter.count5 = 5;
        counter.count6 = 6;
        counter.count7 = 7;

        counter_p = &counter;

        pthread_t thread0;
        pthread_t thread1;
        pthread_t thread2;
        pthread_t thread3;
        pthread_t thread4;
        pthread_t thread5;
        pthread_t thread6;
        pthread_t thread7;

        printf("Creating threads\n");

        //all threads are writing to the same cache line but different bytes, thus causing false sharing
        int ret0 =  pthread_create(&thread0, NULL, &worker_thread, (void*)&counter_p->count0);
        int ret1 =  pthread_create(&thread1, NULL, &worker_thread, (void*)&counter_p->count1);
        int ret2 =  pthread_create(&thread2, NULL, &worker_thread, (void*)&counter_p->count2);
        int ret3 =  pthread_create(&thread3, NULL, &worker_thread, (void*)&counter_p->count3);
        int ret4 =  pthread_create(&thread4, NULL, &worker_thread, (void*)&counter_p->count4);
        int ret5 =  pthread_create(&thread5, NULL, &worker_thread, (void*)&counter_p->count5);
        int ret6 =  pthread_create(&thread6, NULL, &worker_thread, (void*)&counter_p->count6);
        int ret7 =  pthread_create(&thread7, NULL, &worker_thread, (void*)&counter_p->count7);

        if(ret0 != 0 || ret1 != 0 || ret2 != 0 || ret3 != 0 || ret4 != 0 || ret5 != 0 || ret6 != 0 || ret7 != 0) {

                printf("Error: pthread_create() failed\n");
                printf("Thread0: %d\n",ret0);
                printf("Thread1: %d\n",ret1);
                printf("Thread2: %d\n",ret2);
                printf("Thread3: %d\n",ret3);
                printf("Thread4: %d\n",ret4);
                printf("Thread5: %d\n",ret5);
                printf("Thread6: %d\n",ret6);
                printf("Thread7: %d\n",ret7);
                exit(EXIT_FAILURE);
        }


        pthread_join(thread0,NULL);
        pthread_join(thread1,NULL);
        pthread_join(thread2,NULL);
        pthread_join(thread3,NULL);
        pthread_join(thread4,NULL);
        pthread_join(thread5,NULL);
        pthread_join(thread6,NULL);
        pthread_join(thread7,NULL);

}

