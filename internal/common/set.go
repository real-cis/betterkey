// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package common

import (
	"slices"
	"sort"
	"sync"
)

var existMark = struct{}{}

type Set struct {
	lock sync.Mutex
	m    map[string]struct{}
}

func (s *Set) Size() int {
	s.lock.Lock()
	defer s.lock.Unlock()
	return len(s.m)
}

func NewSet() *Set {
	s := &Set{}
	s.m = make(map[string]struct{})
	return s
}

func (s *Set) Add(e string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if e != "" {
		s.m[e] = existMark
	}
}

func (s *Set) AddAll(es []string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, e := range es {
		if e != "" {
			s.m[e] = existMark
		}
	}
}

func (s *Set) Remove(e string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if e != "" {
		delete(s.m, e)
	}
}

func (s *Set) Clear() {
	s.lock.Lock()
	defer s.lock.Unlock()
	//clear(s.m)
	s.m = make(map[string]struct{})
}

func (s *Set) Contains(e string) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	if e != "" {
		_, c := s.m[e]
		return c
	}
	return false
}

func (s *Set) Sorted() []string {
	s.lock.Lock()
	defer s.lock.Unlock()
	l := make([]string, 0, len(s.m))
	for k := range s.m {
		l = append(l, k)
	}
	sort.Strings(l)
	return l
}

func (s *Set) Equals(other []string) bool {
	return slices.Equal(s.Sorted(), other)
}
