/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PROPERTY_TABLE_H_
#define RR_PROPERTY_TABLE_H_

#include <memory>
#include <utility>
#include <vector>

namespace rr {

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
    virtual ~PropertyBase() {}
    virtual void destroy_property(void* v) const = 0;
  };

  std::vector<std::pair<const PropertyBase*, void*>> values;
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
    DEBUG_ASSERT(!get(o));
    T* t = new T();
    o.properties().values.push_back(std::make_pair(
        static_cast<const PropertyTable::PropertyBase*>(this), t));
    return *t;
  }
  T* get(Object& o) const {
    for (auto& p : o.properties().values) {
      if (p.first == this) {
        return static_cast<T*>(p.second);
      }
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
    auto& values = o.properties().values;
    std::unique_ptr<T> result;
    for (auto it = values.begin(); it != values.end(); ++it) {
      if (it->first == this) {
        result = std::unique_ptr<T>(static_cast<T*>(it->second));
        values.erase(it);
        break;
      }
    }
    return result;
  }

protected:
  virtual void destroy_property(void* v) const override {
    delete static_cast<T*>(v);
  }
};

} // namespace rr

#endif /* RR_PROPERTY_TABLE_H_ */
