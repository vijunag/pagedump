# Author: Vijay Nag
#!/usr/bin/python

import os, sys, struct, math
import resource

def Kb(bytes):
  """ Convert bytes to KiloBytes"""
  return (bytes)/1024

def Mb(bytes):
  """ Convert bytest to MegaBytes"""
  return (bytes)/1024/1024

#bits representing pte
class Pte(object):
  """Class representing various page table flags
     associated with a page"""

#Page Table Entry Size
  PTE_SIZE=8
  PAGESIZE = resource.getpagesize()
  PMDSHIFT =  22 #assuming 5 level pagetables
#PTE flags
  PAGE_PRESENT=63
  PAGE_SWAPPED=62
  PAGE_SHARED=61 #page mapped or shared
  PAGE_MAP=61
  PAGE_PFN_MASK=(((1<<55)-1))

#kernel page flags defined in include/uapi/linux/kernel-page-flags.h
  KPF_LOCKED=0
  KPF_ERROR=1
  KPF_REFERENCED=2
  KPF_UPTODATE=3
  KPF_DIRTY=4
  KPF_LRU=5
  KPF_ACTIVE=6
  KPF_SLAB=7
  KPF_WRITEBACK=8
  KPF_RECLAIM=9
  KPF_BUDDY=10
  KPF_MMAP=11
  KPF_ANON=12
  KPF_SWAPCACHE=13
  KPF_SWAPBACKED=14
  KPF_COMPOUND_HEAD=15
  KPF_COMPOUND_TAIL=16
  KPF_HUGE=17
  KPF_UNEVICTABLE=18
  KPF_HWPOISON=19
  KPF_NOPAGE=20
  KPF_KSM=21
  KPF_THP=22
  KPF_BALLOON=23
  KPF_ZERO_PAGE=24
  KPF_IDLE=25

  @staticmethod
  def get_pte_offset(addr): return ((addr)>>12)*Pte.PTE_SIZE

  @staticmethod
  def is_page_present(pte): return (pte&(1<<Pte.PAGE_PRESENT)!=0)

  @staticmethod
  def is_page_swapped(pte): return (pte&(1<<Pte.PAGE_SWAPPED)!=0)

  @staticmethod
  def is_page_mapped(pte): return (pte&(1<<Pte.PAGE_MAP)!=0)

  @staticmethod
  def is_page_shared(pte): return (pte&(1<<Pte.PAGE_SHARED)!=0)

  @staticmethod
  def pte_to_pfn(pte): return (pte&Pte.PAGE_PFN_MASK)

  @staticmethod
  def is_bit_set(bits, flags): return (bits&(1<<(flags))!=0)

def PrintFlags(flags):
  flag_str=""
  enums=[(x,v) for x,v in vars(Pte).iteritems() if x.startswith('KPF')]
  for e in enums:
    if (flags & (1<<e[1])):
      flag_str+="%s|"%e[0]
  return flag_str.rstrip('|')

class VmaEntry(object):
  """
    Every PFN mapping is represented by a VmaEntry
    consisting of pfn itself, map count between processes
    and list of VMA mappings accessing the PFN
  """
  def __init__(self, pfn=None, cnt=1):
    self.pfn = pfn
    self.map_count =cnt
    self.vma_list = list() # list of tuples (pid, (vma_start, vma_end, vma)

class ProcMgr(object):
  """
    This class represents proc file system attributes and methods
  """
  def __init__(self):
    try:
      self.kpgcnt = open("/proc/kpagecount")
      self.kpflags = open("/proc/kpageflags")
      self.PG_MASK = int(math.log(Pte.PAGESIZE,2))
      self.pagemap = dict() #PFN --> (count, (vma1,vma2,....))
    except:
      print "Error opening proc file"
      sys.exit(-1)

  def get_page_map_count(self,pte):
    """
      Read the /proc/kpagecount file for a PFN and get
      the map count
    """
    self.kpgcnt.seek(Pte.pte_to_pfn(pte)*8,os.SEEK_SET)
    count = self.kpgcnt.read(8)
    return struct.unpack('<Q',count)[0]

  def get_page_flags(self,pte):
    """
      Read the /proc/kpageflags file for a PFN and get
      the flags associated with a PFN
    """
    self.kpflags.seek(Pte.pte_to_pfn(pte)*8,os.SEEK_SET)
    flags = self.kpflags.read(8)
    return struct.unpack('<Q',flags)[0]

  def update_pagemap(self,vm_tup):
    """
      Update the mappings from PFN to VMA entry. Create a new PFN if
      the PFN is seen for the first time else increment the map count
    """
    (pfn,pid,vma_start,vma_end,vma,flags)=vm_tup
    val=self.pagemap.get(pfn)
    if not val:
      vmentry=VmaEntry(pfn)
      vmentry.pfn = pfn
      vmentry.vma_list.append((pid,(vma_start,vma_end,vma,flags)))
      self.pagemap[pfn]=vmentry
    else:
      vmentry=self.pagemap.get(pfn)
      vmentry.map_count+=1
      vmentry.vma_list.append((pid,(vma_start,vma_end,vma,flags)))
      self.pagemap[pfn]=vmentry

  def print_maps(self):
    """
      Print all possible PFN-->VMA mappings that have map-count > 1
    """
    for k in self.pagemap.keys():
      pfn=k
      vmentry = self.pagemap[k]
      if vmentry.map_count > 1:
        print "List of processes sharing PFN %x(count=%d)"%(pfn,vmentry.map_count)
        for x in vmentry.vma_list:
          (vma_start,vma_end,vma,flags)=x[1]
          print "--->%d in vmrange[0%x-0%x]@0x%x:[%s]"%(x[0],vma_start,vma_end,vma,PrintFlags(flags))

class ProcPs(object):
  """
    ProcPs encapsulates a process attributes and performs various
    process related operations like page-walk, stats, et al
  """
  def __init__(self, proc, pid):
    try:
      self.pid = pid
      self.proc = proc
      self.mapfile=file("/proc/%s/maps"%pid).read().splitlines(True)
      self.maprange = list()
      self.pgtopfn = dict()
      self.reset_counter()
      for f in self.mapfile:
        split=f.split('-')
        start=long(split[0],16)
        end=long(split[1].split(' ')[0],16)
        self.maprange.append((start,end))
    except:
      print "Error opening proc/maps file for PID=%d"%pid
      sys.exit(-1)

  def reset_counter(self):
      """
        Counter reset routine
      """
      self.swap_pg_cnt = 0
      self.pg_map_cnt = 0
      self.pg_uss_cnt = 0
      self.pg_pss_cnt = 0
      self.pg_file_map_cnt = 0
      self.pg_anon = 0
      self.pg_share_cnt=0
      self.pg_lru_cnt=0
      self.pg_swpbacked_cnt=0

  def update_page_counters(self,vm_pte_entries):
    """
      For the list of PTEs associated with a VMA, account various
      types of pages i.e anon,THP,file-mapped, dirty, swap, cache et
    """
    THP=False
    pg_pss_cnt=0
    (vma_start,vma_end,entries)=vm_pte_entries
    for pg_idx in range(len(entries)):
      pte=entries[pg_idx]
      vma=vma_start+pg_idx*4096
      pgflags=self.proc.get_page_flags(pte)
      pg_present = Pte.is_page_present(pte) #page flags from PTE entry, 63rd bit
      if pg_present:
        pfn=Pte.pte_to_pfn(pte)
        vma_tup=(pfn,self.pid,vma_start,vma_end,vma,pgflags)
        self.proc.update_pagemap(vma_tup)
        self.pg_map_cnt+=1
        if Pte.is_bit_set(pgflags, Pte.KPF_LRU):
          self.pg_lru_cnt+=1
        if Pte.is_bit_set(pgflags,Pte.KPF_ANON):
          self.pg_anon+=1
        if Pte.is_bit_set(pgflags,Pte.KPF_SWAPBACKED):
          self.pg_swpbacked_cnt+=1
        if Pte.is_bit_set(pgflags,Pte.KPF_MMAP):
          self.pg_file_map_cnt+=1
        count=self.proc.get_page_map_count(pte)
        if count==0:
          """If it is a transparent huge page, it is contigous and PSS=RSS"""
          THP=True
        if count:
          pg_pss_cnt+=int(4096.0/count)
      if Pte.is_page_swapped(pgflags):
        self.swap_pg_cnt+=1
    if THP:
        self.pg_pss_cnt = 0
        self.pg_pss_cnt = self.pg_map_cnt*4096
    else:
        self.pg_pss_cnt+=pg_pss_cnt

  def page_walk(self):
    """
      Perform a page walk by going through the VM entries.
      For each VMA segment, lseek to the PTE offset and read
      the corresponding entries
    """
    try:
      f=open("/proc/%s/pagemap"%self.pid)
    except:
      print "Error reading page map for proc pid=%d"%(self.pid)
      sys.exit(-1)

    for x in self.maprange:
      vma_page_len=Pte.get_pte_offset(x[1]-x[0]) #no of page entries to read
      offset=Pte.get_pte_offset(x[0]) #idx to PTE
      f.seek(offset,os.SEEK_SET)
      entries=f.read(vma_page_len)
      if len(entries) > 0:
        vals=struct.unpack('<'+'Q'*(vma_page_len/8),entries)
        vm_entries=(x[0],x[1],vals)
        self.update_page_counters(vm_entries)

  def print_summary(self):
    """
      Print the statistical summary for the process
    """
    print "Process Summary for PID %d"%self.pid
    print "{:<20}:{:<8}Kb".format("Rss",Kb(self.pg_map_cnt*Pte.PAGESIZE))
    print "{:<20}:{:<8}Kb".format("Swap",Kb(self.swap_pg_cnt*Pte.PAGESIZE))
    print "{:<20}:{:<8}Kb".format("USS",Kb(self.pg_uss_cnt*Pte.PAGESIZE))
    print "{:<20}:{:<8}Kb".format("Shared",Kb(self.pg_share_cnt*Pte.PAGESIZE))
    print "{:<20}:{:<8}Kb".format("PSS",Kb(self.pg_pss_cnt))
    print "{:<20}:{:<8}Kb".format("File Mapped",Kb(self.pg_file_map_cnt*Pte.PAGESIZE))
    print "{:<20}:{:<8}Kb".format("Anon",Kb(self.pg_anon*Pte.PAGESIZE))
    print "{:<20}:{:<8}Kb".format("Cache",Kb(self.pg_lru_cnt*Pte.PAGESIZE))
    print "{:<20}:{:<8}Kb".format("SwapBacked",Kb(self.pg_swpbacked_cnt*Pte.PAGESIZE))

def Usage():
  print "pagedump.py <pid1> <pid2>"
  sys.exit(-1)

def main(args):
  p1=None
  p2=None
  if len(args) < 2:
    print Usage()
  p=ProcMgr()
  pid1 = int(args[0])
  p1=ProcPs(p,pid1)
  p1.page_walk()
  pid2 = int(args[1])
  p2=ProcPs(p,pid2)
  p2.page_walk()
  p1.print_summary()
  p2.print_summary()
  p.print_maps()

if __name__ == "__main__":
  main(sys.argv[1:])
