using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using ICSharpCode.SharpZipLib.Zip;

namespace APK_Protect_Check
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            textBox1.DragEnter += new DragEventHandler(textBox1_DragEnter);
            textBox1.DragDrop += new DragEventHandler(textBox1_DragDrop);
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void detectShell(string filePath)
        {
            string judgeRespon = "";
            textBox1.AppendText(filePath + Environment.NewLine);
            using (ZipFile zips = new ZipFile(filePath))
            {
                string Protector = "";
                foreach (ZipEntry tempZip in zips)
                {
                    //textBox1.AppendText(tempZip.Name + Environment.NewLine);
                    if (tempZip.Name.Contains("libchaosvmp.so") || tempZip.Name.Contains("libddog.so") || tempZip.Name.Contains("libfdog.so"))
                    {
                        judgeRespon += "发现娜迦特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("娜迦")) continue;
                        Protector += "娜迦" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libexec.so") || tempZip.Name.Contains("libexecmain.so") || tempZip.Name.Contains("ijiami.dat"))
                    {
                        judgeRespon += "发现爱加密特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("爱加密")) continue;
                        Protector += "爱加密" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libsecexe.so") || tempZip.Name.Contains("libsecmain.so"))
                    {
                        judgeRespon += "发现梆梆特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("梆梆")) continue;
                        Protector += "梆梆" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libDexHelper.so") || tempZip.Name.Contains("libDexHelper-x86.so"))
                    {
                        judgeRespon += "发现梆梆企业版特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("梆梆企业版")) continue;
                        Protector += "梆梆企业版" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libprotectClass.so") || tempZip.Name.Contains("libjiagu.so") || tempZip.Name.Contains("libjiagu.so") ||
                        tempZip.Name.Contains("libjiagu_art.so") || tempZip.Name.Contains("libjiagu.so") || tempZip.Name.Contains("libjiagu_x86.so") ||
                        tempZip.Name.Contains("librsprotect.so") || tempZip.Name.Contains("librsprotect_x86.so") || tempZip.Name.Contains("rsprotect.dat"))

                    {
                        judgeRespon += "发现360加固保特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("360加固保")) continue;
                        Protector += "360加固保" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libegis.so") || tempZip.Name.Contains("libNSaferOnly.so"))
                    {
                        judgeRespon += "发现通付盾特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("通付盾")) continue;
                        Protector += "通付盾" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libnqshield.so"))
                    {
                        judgeRespon += "发现网秦科技特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("网秦")) continue;
                        Protector += "网秦科技" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libbaiduprotect.so"))
                    {
                        judgeRespon += "发现百度特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("百度")) continue;
                        Protector += "百度" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("aliprotect.dat") || tempZip.Name.Contains("libsgmain.so") || tempZip.Name.Contains("libsgsecuritybody.so"))
                    {
                        judgeRespon += "发现阿里聚安全特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("阿里聚安全")) continue;
                        Protector += "阿里聚安全" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libtup.so") || tempZip.Name.Contains("libexec.so") || tempZip.Name.Contains("libshell.so"))
                    {
                        judgeRespon += "发现腾讯乐固特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("腾讯乐固")) continue;
                        Protector += "腾讯乐固" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libtosprotection.armeabi.so") || tempZip.Name.Contains("libtosprotection.armeabi-v7a.so") || tempZip.Name.Contains("libtosprotection.x86.so"))
                    {
                        judgeRespon += "发现腾讯御安全特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("腾讯御安全")) continue;
                        Protector += "腾讯御安全" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libnesec.so"))
                    {
                        judgeRespon += "发现网易易盾特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("网易易盾")) continue;
                        Protector += "网易易盾" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libAPKProtect.so"))
                    {
                        judgeRespon += "发现APKProtector特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("APKProtector")) continue;
                        Protector += "APKProtector" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libkwscmm.so") || tempZip.Name.Contains("libkwscr.so") || tempZip.Name.Contains("libkwslinker.so"))
                    {
                        judgeRespon += "发现几维安全特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("几维安全")) continue;
                        Protector += "几维安全" + Environment.NewLine;
                    }
                    else if (tempZip.Name.Contains("libx3g.so"))
                    {
                        judgeRespon += "发现顶象科技特征文件：" + tempZip.Name + Environment.NewLine;
                        if (Protector.Contains("顶象科技")) continue;
                        Protector += "顶象科技" + Environment.NewLine;
                    }
                }
                if (Protector.Equals(""))
                {
                    textBox1.AppendText("未发现特征文件，可能未加壳，也可能是未知壳" + Environment.NewLine + Environment.NewLine);
                }
                else
                {
                    textBox1.AppendText("该APK可能被以下厂商加固" + Environment.NewLine);
                    textBox1.AppendText(Protector + Environment.NewLine);
                    textBox1.AppendText("判断原因：" + Environment.NewLine);
                    textBox1.AppendText(judgeRespon + Environment.NewLine);
                }
            }
        }

        private void textBox1_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Link;
                this.textBox1.Cursor = System.Windows.Forms.Cursors.Arrow;
            }
            else
            {
                e.Effect = DragDropEffects.None;
            }
        }

        private void textBox1_DragDrop(object sender, DragEventArgs e)
        {
            string path = ((System.Array)e.Data.GetData(DataFormats.FileDrop)).GetValue(0).ToString();
            //MessageBox.Show(path);
            this.textBox1.Cursor = System.Windows.Forms.Cursors.IBeam;
            textBox1.Clear();
            detectShell(path);
        }

        private void aboutAuthorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            MessageBox.Show("APK Protect Detect made by 土豆夫妇", "关于作者", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void openToolStripMenuItem_Click(object sender, EventArgs e)
        {
            textBox1.Clear();
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Multiselect = true;
            dialog.Title = "请选择要检测的APK文件";
            dialog.Filter = "APK files(*.apk)|*.apk";
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                string filePath = dialog.FileName;
                detectShell(filePath);
            }
        }

        private void clearToolStripMenuItem_Click(object sender, EventArgs e)
        {
            textBox1.Clear();
        }
    }
}

