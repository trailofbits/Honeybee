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

typedef int (internal_iterate_nodes_fcn)(node *n, void *context);

hc_tree_set_t hc_tree_set_alloc(hc_tree_set_hash_fcn *hash_fcn, hc_tree_set_is_equal *equals_fcn) {
    hc_tree_set_t tree_set = calloc(1, sizeof(hc_tree_set));
    if (!tree_set) {
        return NULL;
    }

    tree_set->equals_fcn = equals_fcn;
    tree_set->hash_fcn = hash_fcn;

    return tree_set;
}

static int internal_iterate_all_nodes(hc_tree_set_t tree_set, internal_iterate_nodes_fcn iterator, void *context) {
    /* since the tree has an unbounded size, we use a pseudo stack which we re-alloc as we go */
    int result = -1;
    unsigned long long tree_stack_element_count = 1 << 12;
    node **tree_stack = calloc(sizeof(node *), tree_stack_element_count);
    if (!tree_stack) {
        goto CLEANUP;
    }

    unsigned long long tree_stack_count = 1;
    tree_stack[0] = tree_set->root;
    while (tree_stack_count > 0) {
        //Since we use this function for destroying, we need to grab all references we need before calling the fcn
        node *n = tree_stack[--tree_stack_count];

        //Make sure we have space to push the two children
        if (tree_stack_count + 2 >= tree_stack_element_count) {
            node **new_tree_stack = realloc(tree_stack, sizeof(node *) * tree_stack_element_count * 2);
            if (!new_tree_stack) {
                goto CLEANUP;
            }
            tree_stack = new_tree_stack;
            tree_stack_element_count *= 2;
        }

        if (n->left) {
            tree_stack[tree_stack_count++] = n->left;
        }

        if (n->right) {
            tree_stack[tree_stack_count++] = n->right;
        }

        /* we've stashed all information from the node, we can now safely hand it to the iterator */
        if (iterator(n, context)) {
            //Iterator requested stop
            goto CLEANUP;
        }
    }

    result = 0;

    CLEANUP:
    free(tree_stack);
    return result;
}

static int node_free(node *n, void *context) {
    free(n);
    return 0;
}

void hc_tree_set_free(hc_tree_set_t tree_set) {
    internal_iterate_all_nodes(tree_set, node_free, NULL);
}

unsigned long long hc_tree_set_count(hc_tree_set_t tree_set) {
    return tree_set->count;
}

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

struct internal_node_extract_value_context {
    hc_tree_iterator_fcn *iterator_fcn;
    void *user_context;
};

static int internal_node_extract_value_iterator(node *n, void *context) {
    struct internal_node_extract_value_context *ctx_struct = context;
    return ctx_struct->iterator_fcn(n->element, ctx_struct->user_context);;
}

int hc_tree_set_iterate_all(hc_tree_set_t tree_set, hc_tree_iterator_fcn iterator_fcn, void *context) {
    struct internal_node_extract_value_context ctx_struct = {
            .iterator_fcn = iterator_fcn,
            .user_context = context,
    };

    return internal_iterate_all_nodes(tree_set, internal_node_extract_value_iterator, &ctx_struct);
}