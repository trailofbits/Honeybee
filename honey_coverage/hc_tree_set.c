//
// Created by Allison Husain on 2/28/21.
//

#include <stdlib.h>
#include "hc_tree_set.h"

typedef struct node {
    hc_tree_set_hash_type hash;
    void *element;
    struct node *left;
    struct node *right;
} node;

typedef struct internal_hc_tree_set {
    hc_tree_set_hash_fcn *hash_fcn;
    hc_tree_set_is_equal *equals_fcn;

    unsigned long long count;
    node *root;
} hc_tree_set;

/**
 * Creates a new tree set
 * @param hash_fcn The function which generates hashes (which are used as tree values). Note that these values should
 * be as close to random as possible for performance
 * @param equals_fcn A function which returns 0 iff the two values are logically identical
 * @return A tree set, if it could be created, else NULL.
 */
hc_tree_set_t hc_tree_set_alloc(hc_tree_set_hash_fcn *hash_fcn, hc_tree_set_is_equal *equals_fcn) {
    hc_tree_set_t tree_set = calloc(1, sizeof(hc_tree_set));
    if (!tree_set) {
        return NULL;
    }

    tree_set->equals_fcn = equals_fcn;
    tree_set->hash_fcn = hash_fcn;

    return tree_set;
}

/**
 * Frees a tree set
 */
void hc_tree_set_free(hc_tree_set_t tree_set) {
    //TODO: Recursive free won't work for very large trees
    abort();
}

/**
 * Returns the number of elements in the set, O(1)
 */
unsigned long long hc_tree_set_count(hc_tree_set_t tree_set) {
    return tree_set->count;
}

/**
 * Inserts an element into the set
 * Average O(log n)
 * @param tree_set The set to insert into
 * @param element THe element to insert
 * @return 1 if inserted, 0 if already exists, negative on insert error
 */
int hc_tree_set_insert(hc_tree_set_t tree_set, void *element) {
    hc_tree_set_hash_type element_hash = tree_set->hash_fcn(element);
    node **candidate_ptr = &tree_set->root;

    while (*candidate_ptr != NULL) {
        node *candidate = *candidate_ptr;
        if (candidate->hash == element_hash
            && tree_set->equals_fcn(element, candidate->element)) {
            //Element exists -> nothing to insert
            return 0;
        } else if (element_hash < candidate->hash) {
            candidate_ptr = &candidate->left;
        } else {
            //Greater AND collision elements go to the right!!
            candidate_ptr = &candidate->right;
        }
    }

    //If we got here, we've reached a case where we should insert
    node *element_node = calloc(1, sizeof(node));
    if (!element_node) {
        return -1;
    }

    element_node->element = element;
    element_node->hash = element_hash;

    *candidate_ptr = element_node;

    tree_set->count++;

    return 1;
}

/**
 * Checks if the set contains an elements
 * Average O(log n)
 * @return Non-zero if contained, zero if not contained
 */
int hc_tree_set_contains(hc_tree_set_t tree_set, void *element) {
    node *candidate = tree_set->root;
    hc_tree_set_hash_type element_hash = tree_set->hash_fcn(element);
    while (candidate) {
        if (element_hash == candidate->hash && tree_set->equals_fcn(element, candidate->element)) {
            return 1;
        } else if (element_hash < candidate->hash) {
            candidate = candidate->left;
        } else {
            //Greater OR hash collision
            candidate = candidate->right;
        }
    }

    return 0;
}