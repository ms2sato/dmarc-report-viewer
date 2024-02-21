import parse from "https://denopkg.com/nekobato/deno-xml-parser/index.ts";

// IPアドレスからホスト名を取得する関数
async function reverseDnsLookup(ip: string): Promise<string | null> {
  const process = Deno.run({
    cmd: ["nslookup", ip],
    stdout: "piped",
    stderr: "piped",
  });

  const output = await process.output(); // 標準出力の取得
  const outStr = new TextDecoder().decode(output);

  process.close(); // プロセスのクローズ

  // 出力からホスト名を抽出
  const matches = outStr.match(/name = (.+)/);
  if (matches && matches.length > 1) {
    return matches[1].trim();
  } else {
    return null; // ホスト名が見つからない場合
  }
}

// XMLノードからテキストコンテンツを取得する関数
function getTextContent(node: any): string {
  return node && node.content ? node.content : "";
}

// HTMLファイルに出力する関数
async function outputToHtml(htmlContent: string, filePath: string) {
  try {
    await Deno.writeTextFile(filePath, htmlContent);
    console.log(`HTML report has been saved to ${filePath}`);
  } catch (error) {
    console.error("Failed to save HTML report:", error);
  }
}

// XMLデータを受け取り、HTML形式で整形する関数
async function formatDMARCReportAsHtml(xml: string): Promise<string> {
  let htmlContent = `<html>
<head>
<title>DMARC Report</title>
<style>
  body { font-family: Arial, sans-serif; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }
  th { background-color: #f2f2f2; }
</style>
</head>
<body>
<h1>DMARC Report Summary</h1>`;

  try {
    const result = parse(xml);

    // レポートメタデータのセクション
    const reportMetadata = result.root.children.find(
      (child) => child.name === "report_metadata"
    );
    htmlContent += `<h2>Report Metadata</h2>
<table>
<tr><th>Organization</th><td>${getTextContent(
      reportMetadata.children.find((child) => child.name === "org_name")
    )}</td></tr>
<tr><th>Email</th><td>${getTextContent(
      reportMetadata.children.find((child) => child.name === "email")
    )}</td></tr>
<tr><th>Extra Contact Info</th><td>${getTextContent(
      reportMetadata.children.find(
        (child) => child.name === "extra_contact_info"
      )
    )}</td></tr>
<tr><th>Report ID</th><td>${getTextContent(
      reportMetadata.children.find((child) => child.name === "report_id")
    )}</td></tr>
</table>`;

    // ポリシー公開情報のセクション
    const policyPublished = result.root.children.find(
      (child) => child.name === "policy_published"
    );
    htmlContent += `<h2>Policy Published</h2>
<table>
<tr><th>Domain</th><td>${getTextContent(
      policyPublished.children.find((child) => child.name === "domain")
    )}</td></tr>
<tr><th>ADKIM</th><td>${getTextContent(
      policyPublished.children.find((child) => child.name === "adkim")
    )}</td></tr>
<tr><th>ASPF</th><td>${getTextContent(
      policyPublished.children.find((child) => child.name === "aspf")
    )}</td></tr>
<tr><th>P</th><td>${getTextContent(
      policyPublished.children.find((child) => child.name === "p")
    )}</td></tr>
<tr><th>SP</th><td>${getTextContent(
      policyPublished.children.find((child) => child.name === "sp")
    )}</td></tr>
<tr><th>PCT</th><td>${getTextContent(
      policyPublished.children.find((child) => child.name === "pct")
    )}</td></tr>
</table>`;

    // 各レコードのセクション
    htmlContent += `<h2>Records</h2>
    <table>
    <tr><th>Record No</th><th>Source IP</th><th>Hostname</th><th>Count</th><th>SPF Domain</th><th>SPF Result</th><th>DKIM Domain</th><th>DKIM Result</th><th>DKIM Selector</th></tr>`;
    const records = result.root.children.filter(
      (child) => child.name === "record"
    );
    let recordNo = 1;
    for (const record of records) {
      const row = record.children.find((child) => child.name === "row");
      const sourceIp = getTextContent(
        row.children.find((child) => child.name === "source_ip")
      );
      const hostname = await reverseDnsLookup(sourceIp);
      const count = getTextContent(
        row.children.find((child) => child.name === "count")
      );

      const authResults = record.children.find(
        (child) => child.name === "auth_results"
      );
      const spf = authResults.children.find((child) => child.name === "spf");
      const spfDomain = getTextContent(
        spf.children.find((child) => child.name === "domain")
      );
      const spfResult = getTextContent(
        spf.children.find((child) => child.name === "result")
      );

      const dkims = authResults.children.filter(
        (child) => child.name === "dkim"
      );
      let rowColor = "";
      if (
        spfResult === "pass" &&
        dkims.every(
          (dkim) =>
            getTextContent(
              dkim.children.find((child) => child.name === "result")
            ) === "pass"
        )
      ) {
        rowColor = 'style="background-color: green;"';
      } else if (
        spfResult === "pass" ||
        dkims.some(
          (dkim) =>
            getTextContent(
              dkim.children.find((child) => child.name === "result")
            ) === "pass"
        )
      ) {
        rowColor = 'style="background-color: yellow;"';
      }
      if (dkims.length > 0) {
        for (const dkim of dkims) {
          const dkimDomain = getTextContent(
            dkim.children.find((child) => child.name === "domain")
          );
          const dkimResult = getTextContent(
            dkim.children.find((child) => child.name === "result")
          );
          const dkimSelector = getTextContent(
            dkim.children.find((child) => child.name === "selector")
          );

          htmlContent += `<tr ${rowColor}>
<td>${recordNo}</td>
<td>${sourceIp}</td>
<td>${hostname}</td>
<td>${count}</td>
<td>${spfDomain}</td>
<td>${spfResult}</td>
<td>${dkimDomain}</td>
<td>${dkimResult}</td>
<td>${dkimSelector}</td>
</tr>`;
        }
      } else {
        htmlContent += `<tr ${rowColor}>
<td>${recordNo}</td>
<td>${sourceIp}</td>
<td>${hostname}</td>
<td>${count}</td>
<td>${spfDomain}</td>
<td>${spfResult}</td>
<td>N/A</td>
<td>N/A</td>
<td>N/A</td>
</tr>`;
      }
      recordNo++;
    }
    htmlContent += `</table></body></html>`;
    return htmlContent;
  } catch (error) {
    console.error("Failed to format XML as HTML:", error);
    return "";
  }
}

// メイン関数
async function main() {
  console.log("Please input the DMARC XML report file path:");
  const filePath = prompt("File path: ");
  if (filePath) {
    const xml = await Deno.readTextFile(filePath);
    const htmlContent = await formatDMARCReportAsHtml(xml);
    const outputFilePath = `${filePath}.html`;
    await outputToHtml(htmlContent, outputFilePath);
  }
}

main();
