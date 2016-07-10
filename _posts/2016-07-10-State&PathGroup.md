---
layout: post
title: Angr源码分析－State和PathGroup模型
date:   2016-07-10 22:30:00
categories: 程序分析
---

## State

### 1. API

```
state = proj.factory.blank_state()		指定任意地址，返回该地址开始的程序状态
```

```
state = proj.factory.entry_state()		返回程序起始地址(entry point)处的状态
```

```
state = pro.factory.full_init_state()	返回初始化函数处的状态，该初始化函数充当动态加载器的功能，是一个特殊的SimPrecedure，在entry point之前执行
```

### 2. 调用关系

API定义：	angr > factory.py 		line 141	  blank_state()

间接调用：	angr > simos.py		line 174   **state_blank()**

（说明： 另外两个API最终调用的也是state_blank()）

```
def state_blank(self, addr=None, initial_prefix=None, **kwargs)：
	先对用户输入的kwargs进行完善，即若未设置的则使用默认的参数值；
	然后利用kwargs去创建一个SimState对象 state = SimState(**kwargs)；
	最后对state再个性化设置其regs、scratch等属性值。
```

间接调用：	simuvex > s_state.py	line 30	class **SimState**(ana.Storable)

```
其中__init__函数实现：
	设置arch、mode、options（由用户指定和mode共同决定）、注册plugins（由用户指定和options共同决定），以及其他参数；
	注册的状态插件，主要包括寄存器、内存等，SimState就是通过插件集合来实现的，详见 simuvex > plugins 文件夹。
```



## Path

在了解PathGroup模型之前，有必要先了解Path模型，因为前者是后者的集合形式。

### 1. API

```
path = proj.factory.path(state)		返回以该state开始的路径
```

### 2. 调用关系

API定义：	angr > factory.py		line 247		path()

间接调用：	angr > path.py		line 156 		**class Path(object)**

```
其中__init__(self, project, state, path=None)函数实现：
	当path=None时，初始化length、history和callstack（记录历史路径）、previous_run（上一个运
行块）、_merge_*（路径合并时所需的中间变量）；
	当path!=None时，则在当前path的基础上再创建一个新的path对象，继承当前path的大部分属性；
	初始化_run_args、_run（记录运行时状况）等属性，在真实分析中将会用到。
```

#### 其他属性：

​	与历史路径相关的属性，包括历史地址addr_trace、历史运行块trace、历史跳转jumpkinds、历史操作actions等；

​	各种后继路径，包括successors、unconstrained_successors、unsat_successors、mp_successors、nonflat_successors等；

#### 主要方法：

```
def step(self, throw=None, **run_args):		# 核心代码如下
	self.make_sim_run(throw=throw)			# 该函数会修改self._run
	out = [ Path(self._project, s, path=self) for s in self._run.flat_successors ]	 # 以当前path为基础创建后继路径
	return out
```

```
def _make_sim_run(self, throw=None):		# 核心代码如下
	self._run = self._project.factory.sim_run(self.state, **self._run_args)
```

```
def sim_run(self, state, addr=None, jumpkind=None, **block_opts):  # angr > factory line 80
	根据state.scratch.jumpkind的类型来判断下一步该如何运行；
	正常情况下运行 r = sim_block(state, addr=addr, **block_opts)；
	return r		# SimIRSB类型，详见 simuvex > vex > irsb.py (没细看)
	#因此sim_run()即实现了：以当前state为首创建一个内部代码块返回
```



#### 其他方法：

```branch_cause(self)```			返回导致当前路径分叉的变量信息，包括基本块地址、跳转指令地址

```divergence_addr(self, other)```	返回当前路径和other分叉时所在的基本块

```merge()``` 		路径合并  

```unmerge()```		路径分解



## PathGroup

上面已经说明了，PathGroup 是Path的集合，它通过不同“stashes”来管理路径；用户可以对stash进行step forward, filter, merge and move around操作。

PathGroup执行过程中会把paths放到不同的stashes中，包括：active, deadended, found, avoided, pruned, errored, unconstrained, unsat, stashed。

### 1. API

```
path_group = proj.factory.path_group(state)		#返回以该state开始的路径组
```

### 2. 调用关系

API定义：	angr > factory.py		line 262		path_group()

间接调用：	angr > path_group.py 	line 12 		**class PathGroup(ana.Storable)**

```
其中__init__()函数实现：
	初始化save_unconstrained、save_unsat；
	初始化_hooks_step、_hooks_step_path、_hooks_filter、_hooks_complete为[]（与technique相关）；
	初始化stashes。
```



#### 主要方法

```
def explore(self, stash=None, n=None, find=None, avoid=None, find_stash='found', avoid_stash='avoid', cfg=None, num_find=1, step_func=None):	# 核心代码如下
	创建一个exploration_techniques.Explorer对象tech;		# 详见angr > exploration_techniques
	self.use_technique(tech)		# 将tech中定义了的方法添加至_hooks_*属性中，供run()使用
	out = self.run(stash=stash,step_func=step_func,n=n)
	return out
```

```
def run(self, stash=None, n=None, step_func=None):
	until_func = lambda pg: any(h(pg) for h in self._hooks_complete)	
	# 定义运行结束的条件：只要当前pg能满足_hooks_complete列表中的一个函数即可。在Explorer类中该函数为  stash 'found'中的路径个数 >= num_find
	return self.step(n=n, step_func=step_func, until=until_func, stash=stash)	# 对stash中的所有路径step n次，直到满足until条件为止，即能找到一个'found'路径
```

```
step()函数：		每次调用_one_step()对stash中所有路径运行一步，调用n次直到满足until条件退出
_one_step()函数：	对stash中每个符合过滤条件的路径调用_one_path_step()，然后调用_record_step_results()记录返回信息至最新的stashes
_one_path_step()函数：	会调用path.step()运行一步，并将与后继路径相关的信息返回
```

#### 其他方法

```move(self,from_stash,to_stash,filter_func=None)		
move(self,from_stash,to_stash,filter_func=None)		
	将from_stash中满足filter_func的路径移至to_stash	
```

```
merge(self,merge_func=None,stash=None)
	将stash中的所有地址相同的路径以merge_func方式合并
```

```
split(self, stash_splitter=None, stash_ranker=None, path_ranker=None, limit=None, from_stash=None, to_stash=None)
	除self外的前三个参数决定要对from_stash中哪些路径进行分割，将分割后路径放至to_stash
```

```
prune(self, filter_func=None, from_stash=None, to_stash=None)
	对于from_stash中满足filter_func的路径path，若path.errored或not path.state.satisfiable满足的话则将其移至to_stash，一般为'pruned'
```