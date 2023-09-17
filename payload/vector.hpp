#pragma once

#include <iat.hpp>
#include <vm.hpp>

template <typename T>
class vector {
 private:
  T* m_storage;
  u64 m_size;
  u64 m_capacity;

 public:
  vector() : m_storage(nullptr), m_size(0), m_capacity(0) {}

  ~vector() {
    Clear();
    if (m_storage) {
      nt(VirtualFree)(m_storage, 0, MEM_RELEASE);
    }
  }

  T* Reserve() {
    if (m_size >= m_capacity) {
      u64 new_capacity = (m_capacity == 0) ? 1 : m_capacity * 2;
      T* new_storage =
          (T*)nt(VirtualAlloc)(nullptr, new_capacity * sizeof(T),
                               MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

      if (m_storage) {
        vm::memcpy(new_storage, m_storage, m_size * sizeof(T));
        nt(VirtualFree)(m_storage, 0, MEM_RELEASE);
      }

      m_storage = new_storage;
      m_capacity = new_capacity;
    }

    return &m_storage[m_size++];
  }

  u64 GetCapacity() const { return m_capacity; }

  u64 GetSize() const { return m_size; }

  bool IsEmpty() const { return m_size == 0; }

  T* GetStorage() const { return m_storage; }

  T* PushBack(const T& value) {
    T* element = Reserve();
    *element = value;
    return element;
  }

  void Pop() {
    if (m_size > 0) {
      --m_size;
      m_storage[m_size].~T();
    }
  }

  void Clear() {
    for (u64 i = 0; i < m_size; ++i) {
      m_storage[i].~T();
    }
    m_size = 0;
  }

  T& operator[](u64 index) const { return m_storage[index]; }

  u64 Find(const T& element) {
    for (u64 i = 0; i < GetSize(); ++i) {
      if (!vm::memcmp((void*)&m_storage[i], (void*)&element, sizeof(T))) {
        return i;
      }
    }

    return -1;
  }

  void Delete(u64 index) {
    if (index < m_size) {
      m_storage[index].~T();
      if (index != m_size - 1) {
        m_storage[index] = m_storage[m_size - 1];
      }
      --m_size;
    }
  }
};