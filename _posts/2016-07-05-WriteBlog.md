---
layout: post
title: 写一个简单的博客
date:   2016-07-04 11:30:39
categories: 入门
---

## 博客攻略

### 1.安装github

安装github并配置相关信息

### 2.克隆最新博客代码

```
https://github.com/iiebat/iiebat.github.io.git
```

### 3.写博客

### 3.1进入写作目录

```
cd iiebat.github.io #或者是克隆代码时你自己取的名字目录
cd _post
```

#### 3.2创建文件

命名规范 `年-月-日-名称.md` 如： `2016-06-26-VEX.md`

#### 3.3输入博客信息

在文件的开头输入jekyll博客基本信息如：

```
---
layout: post
title: VEX
date: 2016-06-26 13:50:39
categories: 程序分析
---
'categories为博客类别,可以帮助更好的进行分类管理博客'
###'请注意时间:可能是美国时间,比此时时间要早,否则无法显示,可以填的日期早一天'
```

### 3.4编写博客正文

现在可以使用markdown语言编写你的博客正文了

### 4.提交博客

#### 4.1切换到主目录

```
cd ..
```

#### 4.2提交

```
git add -A .
git commit -m "hello"
git push origin master
#后面会要求输入github名字和密码,这个要私信我啦，不能随便给
```

### 5.相关工具

你可能在vim直接编辑看不到实时效果比较郁闷，推荐markdownpad2,可以安装插件画UML图,流程图,写Latex公式等等，你有更好的欢迎推荐。由于*markdowpad*是收费的，因为需要破解，可以上网搜搜！
