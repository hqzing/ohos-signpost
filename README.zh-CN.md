<div align="center">
<p><a href="README.md">English</a> | 简体中文</p>
</div>

# ohos-signpost

在 OpenHarmony 上自动为 `node_modules` 中的二进制文件添加签名。

“signpost”这个名称包含双关含义：
1. **Sign** 表示这是一个签名工具，**post** 则表示它在 `postinstall` 阶段运行。
2. 此外，“signpost”本身有“路标”的意思，与二进制签名时向 ELF 文件添加签名标记的过程相呼应。

## 使用方法

将本包添加到 `devDependencies`，并在 `postinstall` 脚本中调用它。

```json
{
  "devDependencies": {
    "ohos-signpost": "^1.3.0"
  },
  "scripts": {
    "postinstall": "ohos-signpost"
  }
}
```

运行 `npm install` 时，该钩子会自动触发：

* **在 OpenHarmony 上**：扫描 `node_modules`，为所有有效的 ELF 二进制文件（`.so`、`.node` 等）添加签名。
* **在其他平台上**：安全地跳过执行，不会阻止安装过程。

更多信息请参阅[使用指南](USAGE.zh-CN.md)。
