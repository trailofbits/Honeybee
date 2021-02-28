//
// Created by Allison Husain on 2/28/21.
//

#ifndef HONEY_COVERAGE_HC_TREE_SET_H
#define HONEY_COVERAGE_HC_TREE_SET_H

typedef unsigned int hc_tree_set_hash_type;
/**
 * A tree hash function takes in one node and returns that values' hash
 */
typedef hc_tree_set_hash_type (hc_tree_set_hash_fcn)(void *value);

/**
 * A tree equality function returns 0 if the two objects are equal for the purpose of lookups
 */
typedef int (hc_tree_set_is_equal)(void *a, void *b);

typedef struct internal_hc_tree_set *hc_tree_set_t;

/**
 * Creates a new tree set
 * @param hash_fcn The function which generates hashes (which are used as tree values). Note that these values should
 * be as close to random as possible for performance
 * @param equals_fcn A function which returns 0 iff the two values are logically identical
 * @return A tree set, if it could be created, else NULL.
 */
hc_tree_set_t hc_tree_set_alloc(hc_tree_set_hash_fcn *hash_fcn, hc_tree_set_is_equal *equals_fcn);

/**
 * Frees a tree set
 */
void hc_tree_set_free(hc_tree_set_t tree_set);

/**
 * Returns the number of elements in the set, O(1)
 */
unsigned long long hc_tree_set_count(hc_tree_set_t tree_set);

/**
 * Inserts an element into the set
 * Average O(log n)
 * @param tree_set The set to insert into
 * @param element THe element to insert
 * @return 1 if inserted, 0 if already exists, negative on insert error
 */
int hc_tree_set_insert(hc_tree_set_t tree_set, void *element);

/**
 * Checks if the set contains an elements
 * Average O(log n)
 * @return Non-zero if contained, zero if not contained
 */
int hc_tree_set_contains(hc_tree_set_t tree_set, void *element);

#endif //HONEY_COVERAGE_HC_TREE_SET_H
