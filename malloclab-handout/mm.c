#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
 
#include "mm.h"
#include "memlib.h"


#define ALIGNMENT 8
#define ALIGN(size) ((((size) + (ALIGNMENT-1)) / (ALIGNMENT)) * (ALIGNMENT))
#define WSIZE 4
#define DSIZE 8
#define INITCHUNKSIZE (1<<6)
#define CHUNKSIZE (1<<12)
#define LISTMAX 16
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define PACK(size, alloc) ((size) | (alloc))  
#define GET(p) (*(unsigned int *)(p)) 
#define PUT(p, val) (*(unsigned int *)(p) = (val)) 
#define SET_PTR(p, ptr) (*(unsigned int *)(p) = (unsigned)(ptr))
#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)
#define HDRP(ptr) ((char *)(ptr) - WSIZE)
#define FTRP(ptr) ((char *)(ptr) + GET_SIZE(HDRP(ptr)) - DSIZE)
#define NEXT_BLKP(ptr) ((char*)(ptr) + GET_SIZE((char*)(ptr) - WSIZE))
#define PREV_BLKP(ptr) ((char*)(ptr) - GET_SIZE((char*)(ptr) - DSIZE))
#define PRED_PTR(ptr) ((char*)(ptr)) 
#define SUCC_PTR(ptr) ((char*)(ptr) + WSIZE) 
#define PRED(ptr) (*(char **)(ptr)) 
#define SUCC(ptr) (*(char **)(SUCC_PTR(ptr))) 

/*gobal variable*/
void *free_list[LISTMAX];
team_t team = {"csapp_lab","thule","2559454054@qq.com","",""};
/*helper functions*/
static void *extend_heap(size_t size);
static void *coalesce(void *ptr);
static void *place(void *ptr, size_t size);
static void insert_node(void *ptr, size_t size);
static void delete_node(void *ptr);

static void *extend_heap(size_t size)
{
    void *ptr = NULL;
    size = ALIGN(size);
    if((ptr = mem_sbrk(size)) == (NULL))
    {
        return (void *)-1;
    }
    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    PUT(HDRP(NEXT_BLKP(ptr)), PACK(0, 1));
    insert_node(ptr, size);
    return coalesce(ptr);
}

static void insert_node(void *ptr, size_t size)
{
    size_t listnumber = 0;
    void *search_ptr = NULL;
    void *insert_ptr = NULL;
    while((listnumber < LISTMAX - 1)&&(size > 1))
    {
        listnumber++;
        size >>= 1;
    }
    search_ptr = free_list[listnumber];

    if(search_ptr != NULL)
    {
        /*xx->ptr->xx*/
        /*if(insert_ptr != NULL)
        {
            SET_PTR(PRED_PTR(ptr), search_ptr);
            SET_PTR(SUCC_PTR(search_ptr), ptr);
            SET_PTR(SUCC_PTR(ptr), insert_ptr);
            SET_PTR(PRED_PTR(insert_ptr), ptr);
        }*/
        /*list->ptr->xx*/
        if(insert_ptr == NULL)
        {
            SET_PTR(PRED_PTR(ptr), search_ptr);
            SET_PTR(SUCC_PTR(search_ptr), ptr);
            SET_PTR(SUCC_PTR(ptr), NULL);
            free_list[listnumber] = ptr;
        }
    }
    else
    {
        /*xx->ptr
        if(insert_ptr != NULL)
        {
            SET_PTR(PRED_PTR(ptr), NULL);
            SET_PTR(SUCC_PTR(ptr), insert_ptr);
            SET_PTR(PRED_PTR(insert_ptr), ptr);
        }
        free_list->ptr*/
        if(insert_ptr == NULL)
        {
            SET_PTR(PRED_PTR(ptr), NULL);
            SET_PTR(SUCC_PTR(ptr), NULL);
            free_list[listnumber] = ptr;
        }
    }
}

static void delete_node(void *ptr)
{
    size_t size = GET_SIZE(HDRP(ptr));
    size_t listnumber = 0;

    while((size > 1) && (listnumber < (LISTMAX - 1)))
    {
        size>>=1;
        listnumber++;
    }
    if(PRED(ptr) != NULL)
    {
        /*xx->ptr->xx*/
        if(SUCC(ptr) != NULL)
        {
            SET_PTR(SUCC_PTR(PRED(ptr)), SUCC(ptr));
            SET_PTR(PRED_PTR(SUCC(ptr)), PRED(ptr));
        }
        /*free_list->ptr->xx*/
        else
        {
            SET_PTR(SUCC_PTR(PRED(ptr)), NULL);
            free_list[listnumber] = PRED(ptr);
        }
    }
    else
    {
        /*free_list->ptr*/
        if(SUCC(ptr) == NULL)
        {
            free_list[listnumber]=NULL;
        }
        /*xx->ptr*/
        else
        {
            SET_PTR(PRED_PTR(SUCC(ptr)), NULL);
        }
    }
}
static void *coalesce(void *ptr)
{
    _Bool prev_alloc = GET_ALLOC(HDRP(PREV_BLKP(ptr)));
    _Bool next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(ptr)));
    size_t size = GET_SIZE(HDRP(ptr));
    /*afa*/
    if(prev_alloc && next_alloc)
    {
        return ptr;
    }
    /*aff*/
    else if(prev_alloc && !next_alloc)
    {
        delete_node(ptr);
        delete_node(NEXT_BLKP(ptr));
        size += GET_SIZE(HDRP(NEXT_BLKP(ptr)));
        PUT(HDRP(ptr), PACK(size, 0));
        PUT(FTRP(ptr), PACK(size, 0));
    }
    /*aff*/
    else if(!prev_alloc && next_alloc)
    {
        delete_node(ptr);
        delete_node(PREV_BLKP(ptr));
        size += GET_SIZE(HDRP(PREV_BLKP(ptr)));
        PUT(FTRP(ptr), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 0));
        ptr = PREV_BLKP(ptr);
    }
    /*fff*/
    else
    {
        delete_node(PREV_BLKP(ptr));
        delete_node(ptr);
        delete_node(NEXT_BLKP(ptr));
        size += GET_SIZE(HDRP(PREV_BLKP(ptr))) + GET_SIZE(HDRP(NEXT_BLKP(ptr)));
        PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(ptr)), PACK(size, 0));
        ptr = PREV_BLKP(ptr);
    }
    insert_node(ptr, size);
    return ptr;
}

static void *place(void *ptr, size_t size)
{
    size_t now_size = GET_SIZE(HDRP(ptr)	);
    size_t last_remainder = now_size - size;
    delete_node(ptr);
    if(last_remainder < 2 * DSIZE)
    {
        PUT(HDRP(ptr), PACK(now_size, 1));
        PUT(FTRP(ptr), PACK(now_size, 1));
    }
    else if(size > 0x48)
    {
        PUT(HDRP(ptr), PACK(last_remainder, 0));
        PUT(FTRP(ptr), PACK(last_remainder, 0));
        PUT(HDRP(NEXT_BLKP(ptr)), PACK(size, 1));
        PUT(FTRP(NEXT_BLKP(ptr)), PACK(size, 1));
        insert_node(ptr, last_remainder);
        ptr = NEXT_BLKP(ptr);
    }
    else
    {
        PUT(HDRP(ptr), PACK(size, 1));
        PUT(FTRP(ptr), PACK(size, 1));
        PUT(HDRP(NEXT_BLKP(ptr)), PACK(last_remainder, 0));
        PUT(FTRP(NEXT_BLKP(ptr)), PACK(last_remainder, 0));
        insert_node(NEXT_BLKP(ptr), last_remainder);
    }
    return ptr;
}

int mm_init (void)
{
    size_t listnumber = 0;
    void *heap = NULL;
    while(listnumber < LISTMAX)
    {
        free_list[listnumber] = NULL;
        listnumber++;
    }
    
    if((heap = mem_sbrk(2*DSIZE)) == NULL)
    {
        return -1;
    }
    PUT(heap, 0);
    PUT((void *)(heap + WSIZE), PACK(DSIZE, 1));
    PUT((void *)(heap + WSIZE * 2), PACK(DSIZE, 1));
    PUT((void *)(heap + WSIZE * 3), PACK(0, 1));
    
    if(extend_heap(INITCHUNKSIZE) == NULL)
    {
        return -1;
    }
    return 0;
}

void *mm_malloc(size_t size)
{
    if(size <= 0)
    {
        return NULL;
    }
    if(size <= DSIZE)
    {
        size = 2 * DSIZE;
    }
    else
    {
        size = ALIGN(size + DSIZE);
    }

    size_t listnumber = 0;
    void *search_ptr = NULL;
    size_t size_c = size;
    while(listnumber < LISTMAX)
    {
        if(size_c <= 1 && free_list[listnumber] != NULL)
        {
            search_ptr = free_list[listnumber];
            while((search_ptr != NULL) && (size > GET_SIZE(HDRP(search_ptr))))
            {
                search_ptr = PRED(search_ptr);
            }
            if(search_ptr != NULL)
            {
                break;
            }
        }
        size_c >>= 1;
        listnumber++;
    }
    if(search_ptr == NULL)
    {
        if((search_ptr = extend_heap(MAX(size, CHUNKSIZE))) == NULL)
        {
            return NULL;
        }
    }
    search_ptr = place(search_ptr, size);
    return search_ptr;
}

void mm_free(void *ptr)
{
    size_t size = GET_SIZE(HDRP(ptr));

    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));

    insert_node(ptr, size);

    coalesce(ptr);
}

void *mm_realloc(void *ptr, size_t size)
{
    void *new_block = ptr;
    int remainder;

    if (size == 0)
        return NULL;

    if (size <= DSIZE)
    {
        size = 2 * DSIZE;
    }
    else
    {
        size = ALIGN(size + DSIZE);
    }

    if ((remainder = GET_SIZE(HDRP(ptr)) - size) >= 0)
    {
        return ptr;
    }
    else if (!GET_ALLOC(HDRP(NEXT_BLKP(ptr))) || !GET_SIZE(HDRP(NEXT_BLKP(ptr))))
    {
        if ((remainder = GET_SIZE(HDRP(ptr)) + GET_SIZE(HDRP(NEXT_BLKP(ptr))) - size) < 0)
        {
            if (extend_heap(MAX(-remainder, CHUNKSIZE)) == NULL)
                return NULL;
            remainder += MAX(-remainder, CHUNKSIZE);
        }

        delete_node(NEXT_BLKP(ptr));
        PUT(HDRP(ptr), PACK(size + remainder, 1));
        PUT(FTRP(ptr), PACK(size + remainder, 1));
    }
    else
    {
        new_block = mm_malloc(size);
        memcpy(new_block, ptr, GET_SIZE(HDRP(ptr)));
        mm_free(ptr);
    }

    return new_block;
}


