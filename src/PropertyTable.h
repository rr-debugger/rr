/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PROPERTY_TABLE_H_
#define RR_PROPERTY_TABLE_H_

#include <assert.h>

#include <memory>
#include <unordered_map>

template <typename T, typename Object> class Property;

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
  template <typename T, typename Object> friend class Property;

  class PropertyBase {
  public:
    virtual void destroy_property(void* v) const = 0;
  };

  std::unordered_map<const PropertyBase*, void*> values;
};

/**
 * Create an instance of this class to declare a property name.
 * The methods of this class call properties() on their Object parameter to
 * get the PropertyTable.
 */
template <typename T, typename Object>
class Property : protected PropertyTable::PropertyBase {
public:
  Property() {}

  T& create(Object& o) const {
    assert(!get(o));
    T* t = new T();
    o.properties().values[this] = t;
    return *t;
  }
  T* get(Object& o) const {
    auto& properties = o.properties();
    auto e = properties.values.find(this);
    if (e != properties.values.end()) {
      return static_cast<T*>(e->second);
    }
    return nullptr;
  }
  T& get_or_create(Object& o) const {
    T* t = get(o);
    if (t) {
      return *t;
    }
    return create(o);
  }
  std::unique_ptr<T> remove(Object& o) const {
    auto& properties = o.properties();
    auto e = properties.values.find(this);
    std::unique_ptr<T> result;
    if (e != properties.values.end()) {
      result = std::unique_ptr<T>(static_cast<T*>(e->second));
      properties.values.erase(e);
    }
    return result;
  }

protected:
  virtual void destroy_property(void* v) const { delete static_cast<T*>(v); }
};

#endif /* RR_PROPERTY_TABLE_H_ */
