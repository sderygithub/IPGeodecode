"""
Least Recently Used Cache

Usage:

Options:

Examples:

License:

Copyright (c) 2015 Sebastien Dery

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import collections

class LRUCache:
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = collections.OrderedDict()

    def keyIn(self,key):
        return key in self.cache

    def get(self, key):
        try:
            value = self.cache.pop(key)
            self.cache[key] = value
            return value
        except KeyError:
            return -1

    def set(self, key, value):
        try:
            self.cache.pop(key)
        except KeyError:
            if len(self.cache) >= self.capacity:
                self.cache.popitem(last=False)
        self.cache[key] = value



import sys
import unittest
from docopt import docopt

class LRUCacheTest(unittest.TestCase):

    def test_setget(self):
        cache = LRUCache(5)
        cache.set('obj1',1)
        self.assertEqual(cache.get('obj1'),1)

    def test_overcapacity(self):
        cache = LRUCache(5)
        cache.set('obj1',1)
        cache.set('obj2',2)
        cache.set('obj3',3)
        cache.set('obj4',4)
        cache.set('obj5',5)
        cache.set('obj6',6)
        self.assertEqual(cache.get('obj1'),-1)


def main(argv):

    if argv[0] == 'test':
        unittest.main()

if __name__ == "__main__":
    try:
        #main(sys.argv[1:])
        unittest.main()
    except KeyboardInterrupt:
        pass

