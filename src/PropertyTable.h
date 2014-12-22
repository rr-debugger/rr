/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PROPERTY_TABLE_H_
#define RR_PROPERTY_TABLE_H_

#include <assert.h>

#include <memory>
#include <unordered_map>

template <typename T> class Property;

/**
 * A PropertyTable is a heterogenously-typed set of property values.
 * It maps Property<T> (effectively, property names) to values of
 * type T. It owns the property values.
 * Property values can be created, accessed and removed in a type-safe way
 * via the Property class.
 */
class PropertyTable {
public:
  PropertyTable() {}
  ~PropertyTable() {
    for (auto& p : values) {
      p.first->destroy_property(p.second);
    }
  }

private:
  template <typename T> friend class Property;

  class PropertyBase {
  public:
    virtual void destroy_property(void* v) const = 0;
  };

  std::unordered_map<const PropertyBase*, void*> values;
};

/**
 * Create an instance of this class to declare a property name.
 */
template <typename T> class Property : protected PropertyTable::PropertyBase {
public:
  T& create(PropertyTable& properties) const {
    assert(!get(properties));
    T* t = new T();
    properties.values[this] = t;
    return *t;
  }
  T* get(PropertyTable& properties) const {
    auto e = properties.values.find(this);
    if (e != properties.values.end()) {
      return static_cast<T*>(e->second);
    }
    return nullptr;
  }
  T& get_or_create(PropertyTable& properties) const {
    T* t = get(properties);
    if (t) {
      return *t;
    }
    return create(properties);
  }
  std::unique_ptr<T> remove(PropertyTable& properties) const {
    auto e = properties.values.find(this);
    std::unique_ptr<T> result;
    if (e != properties.values.end()) {
      result = std::unique_ptr<T>(static_cast<T*>(e->second));
      properties.values.erase(e);
    }
    return result;
  }

protected:
  virtual void destroy_property(void* v) const {
    delete static_cast<T*>(v);
  }
};

#endif /* RR_PROPERTY_TABLE_H_ */
