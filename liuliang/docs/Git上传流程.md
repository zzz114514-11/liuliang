# Git 上传流程

命令在 D:\liuliang 目录下执行。

## 流程

```
Git 上传
│
├─ 一、准备环境（只做一次）
│   ├─ 装 Git for Windows
│   ├─ git config --global user.name "你的名字"
│   ├─ git config --global user.email "你的邮箱"
│   ├─ git init -b main
│   └─ 写 .gitignore
│
├─ 二、本地提交（日常高频）
│   ├─ git status            看改了什么
│   ├─ git add .             暂存
│   ├─ git commit -m "..."   提交
│   └─ 小步多次，别一次堆一大坨
│
├─ 三、第一次推到远程（只做一次）
│   ├─ Gitee 或 GitHub 上建个空仓库，别勾初始化 README
│   ├─ git remote add origin 仓库地址
│   ├─ git push -u origin main
│   └─ 认证二选一
│       ├─ SSH 密钥：ssh-keygen -t ed25519，公钥贴到平台
│       └─ PAT 令牌：平台设置里生成，密码框填它
│
└─ 四、之后的日常
    ├─ git pull --rebase origin main    推之前先同步
    ├─ 有冲突就手动改，改完 git add 再 git rebase --continue
    ├─ git push
    └─ git log --oneline                看提交历史
```

## 现在的状态

前两步已经做完了，仓库里有十几次提交。现在差第三步：

```bash
cd D:/liuliang
git remote add origin https://gitee.com/你的账号/liuliang.git
git push -u origin main
```

如果远程那边建仓库时勾了 README，push 会被拒，先拉一下再推：

```bash
git pull --rebase origin main --allow-unrelated-histories
git push -u origin main
```

## 踩过的坑

| 现象 | 怎么办 |
|---|---|
| failed to push some refs | 先 `git pull --rebase origin main` |
| GitHub 让输密码 | 填 PAT 令牌，不是登录密码 |
| .gitignore 没生效 | 文件已经被跟踪了，先 `git rm -r --cached 文件名` |
| 想撤掉最后一次提交但保留改动 | `git reset --soft HEAD~1` |
| 提交信息写错了（最近一次） | `git commit --amend` |
