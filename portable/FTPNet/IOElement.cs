using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.UI.Xaml.Media.Imaging;

namespace FTPNet
{
    public class IOElement : IComparable
    {
        public string Name { get; set; }
        public string LastEdit { get; set; }
        public string Path { get; set; }
        public ulong Size { get; set; }
        public int Rigths { get; set; }
        public string RigthsString { get; set; }
        public string Owner { get; set; }
        public string Group { get; set; }
        public bool IsFile { get; set; }
        public string FileType { get; set; }
        public BitmapImage Icon { get; set; }

        public async static Task<List<IOElement>> ParseWindowsFiles(string rawList, string path)
        {
            List<IOElement> files = new List<IOElement>();

            foreach (string item in rawList.Trim().Split('\n'))
            {
                IOElement newElement = new IOElement();

                string trimmedItem = item.Trim();

                int timeEnding = 0;

                for (int i = 8; i < trimmedItem.Length; i++)
                {
                    if (trimmedItem[i] != ' ')
                    {
                        for (int j = i; j < trimmedItem.Length; j++)
                        {
                            if (trimmedItem[i] == ' ')
                            {
                                timeEnding = j;
                                break;
                            }
                        }
                    }
                }

                newElement.LastEdit = trimmedItem.Substring(0, timeEnding).Trim();
                while (newElement.LastEdit.Contains("  "))
                    newElement.LastEdit = newElement.LastEdit.Replace("  ", " ");

                int typeBeginning = 0;
                int typeEnding = 0;

                for (int i = 17; i < trimmedItem.Length; i++)
                {
                    if (trimmedItem[i] != ' ')
                    {
                        typeBeginning = i;
                        break;
                    }
                }

                for (int i = typeBeginning; i < trimmedItem.Length; i++)
                {
                    if (trimmedItem[i] == ' ')
                    {
                        typeEnding = i;
                        break;
                    }
                }

                newElement.FileType = trimmedItem.Substring(typeBeginning, typeEnding - typeBeginning).Replace("<DIR>", "Directory");

                newElement.IsFile = newElement.FileType != "Directory";

                int nameBeginning = 0;
                for (int i = typeEnding + 1; i < trimmedItem.Length; i++)
                {
                    if (trimmedItem[i] != ' ')
                    {
                        nameBeginning = i;
                        break;
                    }
                }

                newElement.Name = trimmedItem.Substring(nameBeginning, trimmedItem.Length - nameBeginning);

                newElement.Path = path;

                //skip those entries
                if (newElement.Name == "." || newElement.Name == "..")
                    continue;

                ulong size = 0;
                ulong.TryParse(newElement.FileType, out size);

                newElement.Size = size;

                if (size != 0)
                    newElement.FileType = newElement.Name.Split('.').Last();

                if (newElement.IsFile)
                {
                    if (newElement.Name.Contains('.'))
                        newElement.FileType = newElement.Name.Substring(newElement.Name.LastIndexOf('.'));
                    else
                        newElement.FileType = newElement.Name;
                }

                //set the icon
                string filename = "_tmp_ext" + newElement.Name.Split('.').Last();
                Windows.Storage.StorageFile iconHelperFile = await ApplicationData.Current.TemporaryFolder.CreateFileAsync(filename, CreationCollisionOption.OpenIfExists);
                Windows.Storage.FileProperties.StorageItemThumbnail iconHelperThumbnail = await iconHelperFile.GetThumbnailAsync(Windows.Storage.FileProperties.ThumbnailMode.SingleItem,
                    16, Windows.Storage.FileProperties.ThumbnailOptions.ResizeThumbnail);
                if (iconHelperThumbnail != null)
                {
                    BitmapImage bitmapImage = new BitmapImage();
                    bitmapImage.SetSource(iconHelperThumbnail.CloneStream());
                    newElement.Icon = bitmapImage;
                }

                files.Add(newElement);
            }

            return files;
        }

        public static async Task<List<IOElement>> ParseLinuxFiles(string rawList, string path)
        {
            List<IOElement> files = new List<IOElement>();

            foreach (string item in rawList.Trim().Split('\n'))
            {
                IOElement newElement = new IOElement();

                string trimmedItem = item.Trim();

                string tmp = trimmedItem.Substring(0, trimmedItem.IndexOf(' ')).Trim();

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' '));

                newElement.IsFile = tmp.StartsWith("d") ? false : true;

                int ownerNumber = 0;
                int groupNumber = 0;
                int publicNumber = 0;

                if (tmp[1] == 'r')
                    ownerNumber += 4;
                if (tmp[2] == 'w')
                    ownerNumber += 2;
                if (tmp[3] == 'x')
                    ownerNumber += 1;

                if (tmp[4] == 'r')
                    groupNumber += 4;
                if (tmp[5] == 'w')
                    groupNumber += 2;
                if (tmp[6] == 'x')
                    groupNumber += 1;

                if (tmp[7] == 'r')
                    publicNumber += 4;
                if (tmp[8] == 'w')
                    publicNumber += 2;
                if (tmp[9] == 'x')
                    publicNumber += 1;

                newElement.Rigths = ownerNumber * 100 + groupNumber * 10 + publicNumber;
                newElement.RigthsString = newElement.Rigths.ToString();

                trimmedItem = trimmedItem.Trim();

                string trash = trimmedItem.Substring(0, trimmedItem.IndexOf(' '));
                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.Owner = trimmedItem.Substring(0, trimmedItem.IndexOf(' '));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.Group = trimmedItem.Substring(0, trimmedItem.IndexOf(' '));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.Size = ulong.Parse(trimmedItem.Substring(0, trimmedItem.IndexOf(' ')));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.LastEdit = trimmedItem.Substring(0, trimmedItem.IndexOf(' '));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.LastEdit += "." + trimmedItem.Substring(0, trimmedItem.IndexOf(' '));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();
                newElement.LastEdit += "." + trimmedItem.Substring(0, trimmedItem.IndexOf(' '));

                trimmedItem = trimmedItem.Remove(0, trimmedItem.IndexOf(' ')).Trim();

                newElement.Name = trimmedItem;

                newElement.Path = path;

                //skip those entries
                if (newElement.Name == "." || newElement.Name == "..")
                    continue;

                if (newElement.IsFile == false)
                    newElement.FileType = "Directory";
                else
                {
                    if (newElement.Name.Contains("."))
                        newElement.FileType = newElement.Name.Substring(newElement.Name.LastIndexOf('.'));
                    else
                        newElement.FileType = newElement.Name;
                }

                //set the icon
                if (newElement.IsFile)
                {
                    string filename = "_tmp_ext" + "." + newElement.Name.Split('.').Last();
                    Windows.Storage.StorageFile iconHelperFile = await ApplicationData.Current.TemporaryFolder.CreateFileAsync(filename, CreationCollisionOption.OpenIfExists);
                    Windows.Storage.FileProperties.StorageItemThumbnail iconHelperThumbnail = await iconHelperFile.GetThumbnailAsync(Windows.Storage.FileProperties.ThumbnailMode.SingleItem,
                        64, Windows.Storage.FileProperties.ThumbnailOptions.ResizeThumbnail);
                    if (iconHelperThumbnail != null)
                    {
                        try
                        {
                            await Windows.ApplicationModel.Core.CoreApplication.MainView.CoreWindow.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                              {
                                  BitmapImage bitmapImage = new BitmapImage();
                                  bitmapImage.SetSource(iconHelperThumbnail.CloneStream());
                                  newElement.Icon = bitmapImage;
                              });
                        }
                        catch (Exception ex) { }
                    }
                }

                files.Add(newElement);
            }

            return files;
        }


        public int CompareTo(object obj)
        {
            IOElement item = (IOElement)obj;

            if (this.IsFile)
            {
                return item.IsFile ? this.Name.CompareTo(item.Name) : 1;
            }
            else
            {
                return !item.IsFile ? this.Name.CompareTo(item.Name) : -1;
            }
        }
    }
}