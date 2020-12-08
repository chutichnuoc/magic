#ifndef QUEUE_STUFF_H
#define QUEUE_STUFF_H

struct queue_stuff
{
	int queue;
	int maxqueue;
	queue_stuff(int i, int m) : queue(i), maxqueue(m) {}
};

#endif