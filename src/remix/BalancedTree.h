/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_BALANCEDTREE_H_
#define RR_BALANCEDTREE_H_

#include <stdint.h>

#include <algorithm>

#include "remix_util.h"

REMIX_TARGET_BEGIN

/**
 * Splay tree implementation from https://en.wikipedia.org/wiki/Splay_tree
 *
 * Has no destructor since we don't support global destructors and we want
 * global variables of this type. Call delete_all() if you need to destroy it.
 */
template <typename K, typename T> class BalancedTree {
public:
  BalancedTree() : root(nullptr) {}

  void delete_all() {
    delete_all(root);
    root = nullptr;
  }

  /*
   * Only call this if you know there isn't already a value
   */
  T* insert(K key, const T& val) {
    Node* z = root;
    Node* p = nullptr;

    while (z) {
      p = z;
      if (z->val < key) {
        z = z->right;
      } else {
        z = z->left;
      }
    }

    z = new Node(val);
    z->parent = p;

    if (!p) {
      root = z;
    } else if (p->val < key) {
      p->right = z;
    } else {
      p->left = z;
    }

    splay(z);
    return &z->val;
  }

  /**
   * Find the largest element <= |key|, or null if all elements are > |key|.
   */
  T* find_less_than_or_equal(K key) {
    bool equal;
    Node* z = find_internal(root, key, &equal);
    return z ? &z->val : nullptr;
  }

  /**
   * Find the smallest element >= |key|, or null if all elements are < |key|.
   */
  T* find_greater_than_or_equal(K key) {
    bool equal;
    Node* z = find_internal_ge(root, key, &equal);
    return z ? &z->val : nullptr;
  }

  T* lookup(K key) {
    bool equal;
    Node* z = find_internal(root, key, &equal);
    return z && equal ? &z->val : nullptr;
  }

  void remove(K key) {
    bool equal;
    Node* z = find_internal(root, key, &equal);
    if (!z || !equal) {
      return;
    }

    if (!z->left) {
      replace(z, z->right);
    } else if (!z->right) {
      replace(z, z->left);
    } else {
      Node* y = subtree_minimum(z->right);
      if (y->parent != z) {
        replace(y, y->right);
        y->right = z->right;
        y->right->parent = y;
      }
      replace(z, y);
      y->left = z->left;
      y->left->parent = y;
    }

    delete z;
  }

private:
  struct Node {
    Node* left;
    Node* right;
    Node* parent;
    T val;
    Node(const T& t) : left(nullptr), right(nullptr), parent(nullptr), val(t) {}
  };
  Node* root;

  static void delete_all(Node* n) {
    if (!n) {
      return;
    }
    n->parent = nullptr;
    while (n) {
      if (n->left) {
        n = n->left;
        continue;
      }
      if (n->right) {
        n = n->right;
        continue;
      }
      Node* parent = n->parent;
      if (parent) {
        if (n == parent->left) {
          parent->left = nullptr;
        } else if (n == parent->right) {
          parent->right = nullptr;
        }
      }
      delete n;
      n = parent;
    }
  }

  /**
   * Find the largest element <= key in the subtree rooted at z.
   */
  Node* find_internal(Node* z, K key, bool* equal) {
    *equal = false;
    if (!z) {
      return nullptr;
    }
    while (true) {
      Node* next;
      if (z->val < key) {
        next = z->right;
      } else if (z->val > key) {
        next = z->left;
      } else {
        splay(z);
        *equal = true;
        return z;
      }
      if (!next) {
        break;
      }
      z = next;
    }
    Node* bottom = z;
    while (z) {
      if (z->val < key) {
        splay(z);
        return z;
      }
      z = z->parent;
    }
    splay(bottom);
    return nullptr;
  }

  /**
   * Find the smallest element >= key in the subtree rooted at z.
   */
  Node* find_internal_ge(Node* z, K key, bool* equal) {
    *equal = false;
    if (!z) {
      return nullptr;
    }
    while (true) {
      Node* next;
      if (z->val < key) {
        next = z->right;
      } else if (z->val > key) {
        next = z->left;
      } else {
        splay(z);
        *equal = true;
        return z;
      }
      if (!next) {
        break;
      }
      z = next;
    }
    Node* bottom = z;
    while (z) {
      if (z->val > key) {
        splay(z);
        return z;
      }
      z = z->parent;
    }
    splay(bottom);
    return nullptr;
  }

  void left_rotate(Node* x) {
    Node* y = x->right;
    if (y) {
      x->right = y->left;
      if (y->left) {
        y->left->parent = x;
      }
      y->parent = x->parent;
    }

    if (!x->parent) {
      root = y;
    } else if (x == x->parent->left) {
      x->parent->left = y;
    } else {
      x->parent->right = y;
    }
    if (y) {
      y->left = x;
    }
    x->parent = y;
  }

  void right_rotate(Node* x) {
    Node* y = x->left;
    if (y) {
      x->left = y->right;
      if (y->right) {
        y->right->parent = x;
      }
      y->parent = x->parent;
    }
    if (!x->parent) {
      root = y;
    } else if (x == x->parent->left) {
      x->parent->left = y;
    } else {
      x->parent->right = y;
    }
    if (y) {
      y->right = x;
    }
    x->parent = y;
  }

  void splay(Node* x) {
    while (x->parent) {
      if (!x->parent->parent) {
        if (x->parent->left == x) {
          right_rotate(x->parent);
        } else {
          left_rotate(x->parent);
        }
      } else if (x->parent->left == x && x->parent->parent->left == x->parent) {
        right_rotate(x->parent->parent);
        right_rotate(x->parent);
      } else if (x->parent->right == x &&
                 x->parent->parent->right == x->parent) {
        left_rotate(x->parent->parent);
        left_rotate(x->parent);
      } else if (x->parent->left == x &&
                 x->parent->parent->right == x->parent) {
        right_rotate(x->parent);
        left_rotate(x->parent);
      } else {
        left_rotate(x->parent);
        right_rotate(x->parent);
      }
    }
  }

  void replace(Node* u, Node* v) {
    if (!u->parent) {
      root = v;
    } else if (u == u->parent->left) {
      u->parent->left = v;
    } else {
      u->parent->right = v;
    }
    if (v) {
      v->parent = u->parent;
    }
  }

  static Node* subtree_minimum(Node* u) {
    while (u->left) {
      u = u->left;
    }
    return u;
  }
};

REMIX_TARGET_END

#endif /* RR_BALANCEDTREE_H_ */
