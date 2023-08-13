package com.tummosoft;

import java.io.File;

import anywheresoftware.b4a.BA.ShortName;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.Properties;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.EnumSet;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;

import anywheresoftware.b4a.AbsObjectWrapper;
import anywheresoftware.b4a.BA;
import anywheresoftware.b4a.keywords.Bit;
import anywheresoftware.b4a.keywords.Common;
import anywheresoftware.b4a.objects.collections.List;
import anywheresoftware.b4a.objects.collections.Map;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import org.apache.commons.codec.digest.DigestUtils;

import java.io.*;
import java.util.*;
import org.w3c.dom.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

@ShortName("jFileSupport")
@BA.Version(1.41f)
public class jFileSupport {

    static {
        System.setProperty("file.encoding", "UTF-8");
        System.setProperty("sun.jnu.encoding", "UTF-8");
    }

    private static final String assetsDir = "AssetsDir";

    public void RennameFile(final String pathname, final String pathname2) {
        new File(pathname).renameTo(new File(pathname2));
    }

    public List ReadDatList(String filePath) throws IOException {
        List List = new List();
        List.Initialize();

        try ( BufferedReader reader = new BufferedReader(new FileReader(filePath, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                List.Add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return List;
    }

    public static String getDirAssets() {
        return assetsDir;
    }

    /**
     * Returns the temporary folder.
     */
    public static String getDirTemp() {
        return System.getProperty("java.io.tmpdir");
    }
    
    public void ReadAllInFolderToXML(String path, String SaveAs) {
        try {
            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
            Document doc = docBuilder.newDocument();
            
            Element rootElement = doc.createElement("FolderContent");
            doc.appendChild(rootElement);

            File folder = new File(path);
            if (folder.exists() && folder.isDirectory()) {
                listFilesAndFolders(folder, rootElement, doc);
            } else {
                BA.LogError("Folder does not exits!");
            }

            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");

            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(new File(SaveAs));

            transformer.transform(source, result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void listFilesAndFolders(File folder, Element parentElement, Document doc) {
        File[] files = folder.listFiles();
        for (File file : files) {
            Element fileElement = doc.createElement("FileOrFolder");
            parentElement.appendChild(fileElement);

            Element nameElement = doc.createElement("Name");
            nameElement.appendChild(doc.createTextNode(file.getName()));
            fileElement.appendChild(nameElement);

            if (file.isFile()) {
                Element typeElement = doc.createElement("Type");
                typeElement.appendChild(doc.createTextNode("File"));
                fileElement.appendChild(typeElement);
                
                Element sizeElement = doc.createElement("Size");
                sizeElement.appendChild(doc.createTextNode(String.valueOf(file.length())));
                fileElement.appendChild(sizeElement);
                
                Element lastModified = doc.createElement("LastModified");
                lastModified.appendChild(doc.createTextNode(String.valueOf(file.lastModified())));
                fileElement.appendChild(lastModified);
                
            } else if (file.isDirectory()) {
                Element typeElement = doc.createElement("Type");
                typeElement.appendChild(doc.createTextNode("Folder"));
                fileElement.appendChild(typeElement);

                listFilesAndFolders(file, fileElement, doc); 
            }
        }
    }
    
    public String ReadAllFolderToJson(String path, String contextPath) {        
        String jsonString = "";
        try {
            JSONObject rootObject = new JSONObject();
            JSONArray filesArray = new JSONArray();
            rootObject.put("FolderContent", filesArray);

            File folder = new File(path);
            if (folder.exists() && folder.isDirectory()) {
                listFilesAndFolders(folder, filesArray, contextPath);
            } else {
                BA.LogError("Folder not exits!");                
            }
            jsonString = rootObject.toString(4);            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return jsonString;
    }
    
    private static void listFilesAndFolders(File folder, JSONArray filesArray, String contextPath) {
        File[] files = folder.listFiles();
         String curentFolder = "";
        for (File file : files) {
            JSONObject fileObject = new JSONObject();          
             
            if (file.isFile()) {
                fileObject.put("Name", file.getName());
                fileObject.put("Type", "File");
                fileObject.put("Size", file.length());
                fileObject.put("ModifiedTime", file.lastModified());
            } else if (file.isDirectory()) {
                fileObject.put("Name", file.getName());               
                fileObject.put("Type", "Folder");
                JSONArray subFilesArray = new JSONArray();
                listFilesAndFolders(file, subFilesArray, contextPath); 
                fileObject.put("Contents", subFilesArray);
            }

            filesArray.put(fileObject);
        }
    }
    
    public int CheckFileSignatures(String filePath) {
        int result = -1;
        try (FileInputStream inputStream = new FileInputStream(filePath)) {
            byte[] signatureBytes = new byte[8];
            int bytesRead = inputStream.read(signatureBytes);

            if (bytesRead == 8) {
                String hexSignature = bytesToHex(signatureBytes);
                BA.LogInfo("Hex Signature: " + hexSignature);
                if (checkSignature(hexSignature)) {
                    result = 0;
                    BA.LogInfo("File type is recognized.");                    
                } else {
                    result = 1;
                    BA.LogInfo("File type is not recognized.");                    
                }
            } else {
                BA.LogInfo("File is too short to determine the signature.");                                    
                result = 2;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        return result;
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }

    static public String[] recognizedSignatures;
    
    private static boolean checkSignature(String hexSignature) {
        // Add more signatures and corresponding file types as needed
        if (recognizedSignatures == null) {
            recognizedSignatures = new String[] {
            "504B0304", // ZIP archive
            "25504446", // PDF file
            "47494638",  // GIF image
            "504B0506", // EPUB, JAR, ODF, OOXML
            "504B0708", // EPUB, JAR, ODF, OOXML
            "FFFB", //MP3
            "FFF3", //MP3
            "FFF2", //MP3
            "FF0A", //JPEG                
            "FFD8FF", //
            "FFD8FF",
            "FFD8FF",
            "FFD8FF",
            "89504E470D0A1A0A",
            "52494646"
        };
        }
        
        for (String recognizedSig : recognizedSignatures) {
            if (hexSignature.startsWith(recognizedSig)) {
                return true;
            }
        }
        return false;
    }
    /**
     * Returns the application folder.
     */
    public static String getDirApp() {
        return System.getProperty("user.dir");
    }
    private static int os;

    /**
     * Returns the path to a folder that is suitable for writing files. On
     * Windows, folders under Program Files are read-only. Therefore File.DirApp
     * will be read-only as well. On Windows it returns the path to the user
     * data folder. For example: C:\Users\[user name]\AppData\Roaming\[AppName]
     * On Mac it returns ~/Library/Application Support/[AppName] On Linux it
     * returns the same path as File.DirApp.
     */
    public static String DirData(String AppName) throws IOException {
        if (os == 0) {
            String s = System.getProperty("os.name", "").toLowerCase(BA.cul);
            if (s.contains("win")) {
                os = 1; //windows
            } else if (s.contains("mac")) {
                os = 2; //mac
            } else {
                os = 3; //linux
            }
        }
        if (os == 1 || os == 2) {
            String res;
            if (os == 1) {
                res = jFileSupport.Combine(System.getenv("AppData"), AppName);
            } else {
                res = jFileSupport.Combine(Common.GetSystemProperty("user.home", ""), "Library/Application Support/" + AppName);
            }
            if (jFileSupport.Exists(res, "") == false) {
                jFileSupport.MakeDir(res, "");
            }
            return res;
        } else {
            return jFileSupport.getDirApp();
        }

    }

    /**
     * Returns the path of the file or folder parent.
     */
    public static String GetFileParent(String FileName) {
        String s = new java.io.File(FileName).getParent();
        return s == null ? "" : s;
    }

    /**
     * Returns the file name from the full path (or the directory name in case
     * of a directory).
     */
    public static String GetName(String FilePath) {
        return new java.io.File(FilePath).getName();
    }

    /**
     * Returns true if the specified FileName exists (file or folder) in the
     * specified Dir. Note that the file system is case sensitive. This method
     * does not support File.DirAssets.
     *
     * Example:<code>
     *If File.Exists(File.DirApp, "MyFile.txt") Then ...</code>
     */
    public static boolean Exists(String Dir, String FileName) throws IOException {
        if ("".equals(Dir)) {
            Dir = null;
        }
        return new java.io.File(Dir, FileName).exists();
    }

    /**
     * Deletes the specified file. If the file name is a directory then it must
     * be empty in order to be deleted. Returns true if the file was
     * successfully deleted. Files in the assets folder cannot be deleted.
     */
    public static boolean Delete(String Dir, String FileName) {
        if ("".equals(Dir)) {
            Dir = null;
        }
        return new java.io.File(Dir, FileName).delete();
    }

    /**
     * Creates the given folder (creates all folders as needed). null     Example:<code>
	 *File.MakeDir(File.DirApp, "music/90")</code>
     */
    public static void MakeDir(String Parent, String Dir) {
        java.io.File file = new java.io.File(Parent, Dir);
        file.mkdirs();
    }

    public String FileMetadataToJson(String path) {
        String result = "";
        try {
            File file = new File(path);
            if (file.exists()) {
                JSONObject fileData = new JSONObject();
                if (Files.isRegularFile(file.toPath())) {
                    Set<PosixFilePermission> permissions = null;
                    try {
                        PosixFileAttributes posixAttributes = Files.readAttributes(file.toPath(), PosixFileAttributes.class);
                        permissions = posixAttributes.permissions();
                    } catch (UnsupportedOperationException e) {
                        BA.LogError("Not support.");
                    }

                    if (permissions != null) {
                        JSONArray permissionsArray = new JSONArray();
                        for (PosixFilePermission permission : permissions) {
                            permissionsArray.put(permission.toString());
                        }
                        fileData.put("permissions", permissionsArray);
                    }
                }

                // Kiểm tra thuộc tính cơ bản
                BasicFileAttributes basicAttributes = Files.readAttributes(file.toPath(), BasicFileAttributes.class);
                FileTime creationTime = basicAttributes.creationTime();
                FileTime lastAccessTime = basicAttributes.lastAccessTime();
                FileTime lastModifiedTime = basicAttributes.lastModifiedTime();
                
                long size = basicAttributes.size();
                
                fileData.put("creationTime", creationTime.toString());
                fileData.put("lastAccessTime", lastAccessTime.toString());
                fileData.put("lastModifiedTime", lastModifiedTime.toString());
                fileData.put("size", size);

                result = fileData.toString(4);
            } else {
                BA.LogError("File not found.");
            }
        } catch (IOException e) {
            BA.LogError(e.getMessage());
        }

        return result;
    }
    
    public static String getFileChecksum(String Dir, String FileName) throws IOException {
        File file = new File(Dir, FileName);
        FileInputStream fis = new FileInputStream(file);
        String checksum = DigestUtils.md5Hex(fis); // You can also use other algorithms like SHA-1 or SHA-256
        fis.close();
        return checksum;
    }
    
    public static void setFilePermissions(String Dir, String FileName, String permissions) throws IOException {
         java.io.File filename = new java.io.File(Dir, FileName);
         
        String s = System.getProperty("os.name", "").toLowerCase(BA.cul);
        if (s.contains("win")) {
            BA.LogError("OS not support");
            return;
        }
        Path filePath = filename.toPath();
        Set<PosixFilePermission> filePermissions = PosixFilePermissions.fromString(permissions);
        Files.setPosixFilePermissions(filePath, filePermissions);
    }

    public static void setDirectoryPermissions(String Path, String permissions) throws IOException {
        java.io.File folder = new java.io.File(Path, "");
        
        String s = System.getProperty("os.name", "").toLowerCase(BA.cul);
        if (s.contains("win")) {
            BA.LogError("OS not support");
            return;
        }
        Path folderPath = folder.toPath();
        Set<PosixFilePermission> directoryPermissions = PosixFilePermissions.fromString(permissions);
        Files.setPosixFilePermissions(folderPath, directoryPermissions);
    }

    /**
     * Returns the size in bytes of the specified file. This method does not
     * support files in the assets folder.
     */
    public static long Size(String Dir, String FileName) {
        if ("".equals(Dir)) {
            Dir = null;
        }
        return new java.io.File(Dir, FileName).length();
    }

    /**
     * Returns the last modified date of the specified file. This method does
     * not support files in the assets folder. null     Example:<code>
	 *Dim d As Long
     *d = File.LastModified(File.DirApp, "1.txt")
     *Msgbox(DateTime.Date(d), "Last modified")</code>
     */
    public static long LastModified(String Dir, String FileName) {
        if ("".equals(Dir)) {
            Dir = null;
        }
        return new java.io.File(Dir, FileName).lastModified();
    }

    /**
     * Tests whether the specified file is a directory.
     */
    public static boolean IsDirectory(String Dir, String FileName) {
        if ("".equals(Dir)) {
            Dir = null;
        }
        return new java.io.File(Dir, FileName).isDirectory();
    }

    /**
     * Returns a Uri string ("file://...") that points to the given file.
     */
    public static String GetUri(String Dir, String FileName) {
        if (Dir.equals(jFileSupport.getDirAssets())) {
            URL u = jFileSupport.class.getResource("/Files/" + FileName);
            if (u == null) {
                throw new RuntimeException("Asset file not found: " + FileName);
            }
            return u.toString();
        } else {
            return new java.io.File(jFileSupport.Combine(Dir, FileName)).toURI().toString();
        }
    }

    /**
     * Returns the full path to the given file. This methods does not support
     * files in the assets folder.
     */
    public static String Combine(String Dir, String FileName) {
        if ("".equals(Dir)) {
            Dir = null;
        }
        return new java.io.File(Dir, FileName).toString();
    }

    /**
     * Returns a read only list with all the files and directories which are
     * stored in the specified path. An uninitialized list will be returned if
     * the folder is not accessible. This method does not support the assets
     * folder.
     */
    @SuppressWarnings("unchecked")
    public static anywheresoftware.b4a.objects.collections.List ListFiles(String Dir) throws IOException {
        anywheresoftware.b4a.objects.collections.List list = new anywheresoftware.b4a.objects.collections.List();
        if (Dir.equals(assetsDir) == false) {
            java.io.File folder = new java.io.File(Dir);
            if (!folder.isDirectory()) {
                throw new IOException(Dir + " is not a folder.");
            }
            String[] f = folder.list();
            if (f != null) {
                list.setObject((java.util.List) Arrays.asList(f));
            }
        } else {
            throw new RuntimeException("Cannot list assets files");
        }
        return list;
    }

    /**
     * Opens the specified file name which is located in the Dir folder for
     * reading. Note that the file names are case sensitive.
     */
    public static InputStreamWrapper OpenInput(String Dir, String FileName) throws IOException {

        InputStreamWrapper is = new InputStreamWrapper();
        if (Dir.equals(assetsDir)) {
            InputStream in = File.class.getResourceAsStream("/Files/" + FileName);
            if (in == null) {
                throw new FileNotFoundException(FileName);
            }

            is.setObject(in);
        } else {
            if ("".equals(Dir)) {
                Dir = null;
            }
            is.setObject(new BufferedInputStream(new FileInputStream(new java.io.File(Dir, FileName)),
                    8192));
        }
        return is;
    }

    /**
     * Reads the entire file and returns a List with all lines (as strings). null     Example:<code>
	 *Dim List1 As List
     *List1 = File.ReadList(File.DirApp, "1.txt")
     *For i = 0 to List1.Size - 1
     *	Log(List1.Get(i))
     *Next </code>
     */
    public static List ReadList(String Dir, String FileName) throws IOException {
        InputStreamWrapper in = OpenInput(Dir, FileName);
        TextReaderWrapper tr = new TextReaderWrapper();
        tr.Initialize(in.getObject());
        return tr.ReadList();
    }

    /**
     * Writes each item in the list as a single line. Note that a value
     * containing CRLF will be saved as two lines (which will return two item
     * when read with ReadList). All values will be converted to strings. null     Example:<code>
	 *File.WriteList (File.DirApp, "mylist.txt", List1)</code>
     */
    public static void WriteList(String Dir, String FileName, List List) throws IOException {
        OutputStreamWrapper out = OpenOutput(Dir, FileName, false);
        TextWriterWrapper tw = new TextWriterWrapper();
        tw.Initialize(out.getObject());
        tw.WriteList(List);
        tw.Close();
    }

    /**
     * Writes the given text to a new file. null     Example:<code>
	 *File.WriteString(File.DirApp, "1.txt", "Some text")</code>
     */
    public static void WriteString(String Dir, String FileName, String Text) throws IOException {
        OutputStreamWrapper out = OpenOutput(Dir, FileName, false);
        TextWriterWrapper tw = new TextWriterWrapper();
        tw.Initialize(out.getObject());
        tw.Write(Text);
        tw.Close();
    }

    /**
     * Reads the file and returns its content as a string. null     Example:<code>
	 *Dim text As String
     *text = File.ReadString(File.DirApp, "1.txt")</code>
     */
    public static String ReadString(String Dir, String FileName) throws IOException {
        InputStreamWrapper in = OpenInput(Dir, FileName);
        TextReaderWrapper tr = new TextReaderWrapper();
        tr.Initialize(in.getObject());
        String res = tr.ReadAll();
        in.Close();
        return res;
    }

    /**
     * Creates a new file and writes the given map. Each key value pair is
     * written as a single line. All values are converted to strings. See this
     * link for more information about the actual format: <link>Properties
     * format|http://en.wikipedia.org/wiki/.properties</link>. You can use
     * File.ReadMap to read this file.
     */
    public static void WriteMap(String Dir, String FileName, Map Map) throws IOException {
        OutputStreamWrapper out = OpenOutput(Dir, FileName, false);

        Properties p = new Properties();

        java.util.Map<Object, Object> m = Map.getObject();
        for (Entry<Object, Object> e : m.entrySet()) {
            p.setProperty(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
        }

        p.store(new OutputStreamWriter(out.getObject(), "UTF-8"), null);

        out.Close();
    }

    /**
     * Reads the file and parses each line as a key-value pair (of strings). See
     * this link for more information about the actual format: <link>Properties
     * format|http://en.wikipedia.org/wiki/.properties</link>. You can use
     * File.WriteMap to write a map to a file. Note that the order of items in
     * the map may not be the same as the order in the file.
     */
    public static Map ReadMap(String Dir, String FileName) throws IOException {
        return ReadMap2(Dir, FileName, null);
    }

    /**
     * Similar to ReadMap. ReadMap2 adds the items to the given Map. By using
     * ReadMap2 with a populated map you can force the items order as needed. null     Example:<code>
	 *Dim m As Map
     *m.Initialize
     *m.Put("Item #1", "")
     *m.Put("Item #2", "")
     *m = File.ReadMap2(File.DirApp, "settings.txt", m)</code>
     */
    public static Map ReadMap2(String Dir, String FileName, Map Map) throws IOException {
        InputStreamWrapper in = OpenInput(Dir, FileName);

        Properties p = new Properties();

        p.load(in.getObject());
        if (Map == null) {
            Map = new Map();
        }
        if (Map.IsInitialized() == false) {
            Map.Initialize();
        }
        for (Entry<Object, Object> e : p.entrySet()) {
            Map.Put(e.getKey(), e.getValue());
        }
        in.Close();
        return Map;
    }

    public Map ReadMapUnicode(String Dir, String FileName) throws IOException {
        Properties properties = new Properties();
        Map propertiesMap = new Map();
        propertiesMap.Initialize();
        java.io.File path1 = new java.io.File(Dir, FileName);
        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(path1), "UTF-8"));

        properties.load(br);

        for (String key : properties.stringPropertyNames()) {
            String value = properties.getProperty(key);
            propertiesMap.Put(key, value);
        }

        br.close();

        return propertiesMap;
    }

    /**
     * Copies the specified source file to the target path. Note that it is not
     * possible to copy files to the Assets folder.
     */
    public static void Copy(String DirSource, String FileSource, String DirTarget, String FileTarget) throws IOException {
        jFileSupport.Delete(DirTarget, FileTarget);
        InputStream in = jFileSupport.OpenInput(DirSource, FileSource).getObject();
        OutputStream out = jFileSupport.OpenOutput(DirTarget, FileTarget, false).getObject();
        Copy2(in, out);
        in.close();
        out.close();
    }

    /**
     * Copies all the available data from the input stream into the output
     * stream. The input stream is automatically closed at the end.
     */
    public static void Copy2(InputStream In, OutputStream Out) throws IOException {
        byte[] buffer = new byte[8192];
        int count = 0;
        while ((count = In.read(buffer)) > 0) {
            Out.write(buffer, 0, count);
        }
        In.close();
    }

    /**
     * Asynchronously copies all the available data from the input stream into
     * the output stream. The input stream is automatically closed at the end.
     * Returns an object that should be used as the sender filter. null     Example:<code>
	 *Wait For (File.Copy2Async(in, out)) Complete (Success As Boolean)
     *Log("Success: " & Success)</code>
     */
    public static Object Copy2Async(final BA ba, final InputStream In, final OutputStream Out) {
        final Object senderFilter = new Object();
        BA.runAsync(ba, senderFilter, "complete", new Object[]{false}, new Callable<Object[]>() {

            @Override
            public Object[] call() throws Exception {
                Copy2(In, Out);
                return new Object[]{true};
            }
        });
        return senderFilter;
    }

    /**
     * Asynchronous version of ListFiles. Should be used with Wait For. null     Example:<code>
	 *Wait For (File.ListFilesAsync(Dir)) Complete (Success As Boolean, Files As List)</code>
     */
    public static Object ListFilesAsync(final BA ba, final String Dir) {
        final Object senderFilter = new Object();
        BA.runAsync(ba, senderFilter, "complete", new Object[]{false, new List()}, new Callable<Object[]>() {
            @Override
            public Object[] call() throws Exception {
                List l = ListFiles(Dir);
                return new Object[]{true, l};
            }
        });
        return senderFilter;
    }

    /**
     * Asynchronously copies the source file to the target path. Note that it is
     * not possible to copy files to the Assets folder. Returns an object that
     * should be used as the sender filter. Example: <code>
     *Wait For (File.CopyAsync(File.DirAssets, "1.txt", File.DirTemp, "1.txt")) Complete (Success As Boolean)
     *Log("Success: " & Success)</code>
     */
    public static Object CopyAsync(BA ba, final String DirSource, final String FileSource, final String DirTarget, final String FileTarget) throws IOException {

        final Object senderFilter = new Object();
        BA.runAsync(ba, senderFilter, "complete", new Object[]{false}, new Callable<Object[]>() {
            @Override
            public Object[] call() throws Exception {
                Copy(DirSource, FileSource, DirTarget, FileTarget);
                return new Object[]{true};
            }
        });
        return senderFilter;
    }

    /**
     * Reads the data from the given file.
     */
    public static byte[] ReadBytes(String Dir, String FileName) throws IOException {
        return Bit.InputStreamToBytes(OpenInput(Dir, FileName).getObject());
    }

    /**
     * Writes the data to the given file.
     */
    public static void WriteBytes(String Dir, String FileName, byte[] Data) throws IOException {
        OutputStreamWrapper o = OpenOutput(Dir, FileName, false);
        try {
            o.WriteBytes(Data, 0, Data.length);
        } finally {
            o.Close();
        }
    }

    /**
     * Opens (or creates) the specified file which is located in the Dir folder
     * for writing. If Append is true then the new data will be written at the
     * end of the existing file. This method does not support files in the
     * assets folder.
     */
    public static OutputStreamWrapper OpenOutput(String Dir, String FileName, boolean Append) throws FileNotFoundException {
        if ("".equals(Dir)) {
            Dir = null;
        }
        OutputStreamWrapper o = new OutputStreamWrapper();
        o.setObject(
                new BufferedOutputStream(new FileOutputStream(new java.io.File(Dir, FileName), Append)));

        return o;
    }

    /**
     * A stream that you can read from. Usually you will pass the stream to a
     * "higher level" object like TextReader that will handle the reading. You
     * can use File.OpenInput to get a file input stream.
     */
    @ShortName("InputStream")
    public static class InputStreamWrapper extends AbsObjectWrapper<InputStream> {

        /**
         * Use File.OpenInput to get a file input stream. This method should be
         * used to read data from a bytes array. Initializes the input stream
         * and sets it to read from the specified bytes array. StartOffset - The
         * first byte that will be read. MaxCount - Maximum number of bytes to
         * read.
         */
        public void InitializeFromBytesArray(byte[] Buffer, int StartOffset, int MaxCount) {
            setObject(new ByteArrayInputStream(Buffer, StartOffset, MaxCount));
        }

        /**
         * Closes the stream.
         */
        public void Close() throws IOException {
            getObject().close();
        }

        /**
         * Reads up to MaxCount bytes from the stream and writes it to the given
         * Buffer. The first byte will be written at StartOffset. Returns the
         * number of bytes actually read. Returns -1 if there are no more bytes
         * to read. Otherwise returns at least one byte. null         Example:<code>
		 *Dim buffer(1024) As byte
         *count = InputStream1.ReadBytes(buffer, 0, buffer.length)</code>
         */
        public int ReadBytes(byte[] Buffer, int StartOffset, int MaxCount) throws IOException {
            return getObject().read(Buffer, StartOffset, MaxCount);
        }

        /**
         * Returns an estimation of the number of bytes available without
         * blocking.
         */
        public int BytesAvailable() throws IOException {
            return getObject().available();
        }
    }

    /**
     * A stream that you can write to. Usually you will pass the stream to a
     * "higher level" object like TextWriter which will handle the writing. Use
     * File.OpenOutput to get a file output stream.
     */
    @ShortName("OutputStream")
    public static class OutputStreamWrapper extends AbsObjectWrapper<OutputStream> {

        /**
         * Use File.OpenOutput to get a file output stream. This method should
         * be used to write data to a bytes array. StartSize - The starting size
         * of the internal bytes array. The size will increase if needed.
         */
        public void InitializeToBytesArray(int StartSize) {
            setObject(new ByteArrayOutputStream(StartSize));
        }

        /**
         * Returns a copy of the internal bytes array. Can only be used when the
         * output stream was initialized with InitializeToBytesArray.
         */
        public byte[] ToBytesArray() {
            if (!(getObject() instanceof ByteArrayOutputStream)) {
                throw new RuntimeException("ToBytes can only be called after InitializeToBytesArray.");
            }
            return ((ByteArrayOutputStream) getObject()).toByteArray();

        }

        /**
         * Closes the stream.
         */
        public void Close() throws IOException {
            getObject().close();
        }

        /**
         * Flushes any buffered data.
         */
        public void Flush() throws IOException {
            getObject().flush();
        }

        /**
         * Writes the buffer to the stream. The first byte to be written is
         * Buffer(StartOffset), and the last is Buffer(StartOffset + Length -
         * 1).
         */
        public void WriteBytes(byte[] Buffer, int StartOffset, int Length) throws IOException {
            getObject().write(Buffer, StartOffset, Length);
        }
    }

    /**
     * Writes text to the underlying stream.<br/>
     *
     * Example:<code>
     *Dim Writer As TextWriter
     *Writer.Initialize(File.OpenOutput(File.DirDefaultExternal, "1.txt", False))
     *Writer.WriteLine("This is the first line.")
     *Writer.WriteLine("This is the second line.")
     *Writer.Close</code>
     *
     */
    @ShortName("TextWriter")
    public static class TextWriterWrapper extends AbsObjectWrapper<BufferedWriter> {

        /**
         * Initializes this object by wrapping the given OutputStream using the
         * UTF8 encoding.
         */
        public void Initialize(OutputStream OutputStream) {
            setObject(new BufferedWriter(new OutputStreamWriter(OutputStream, Charset.forName("UTF8")),
                    4096));
        }

        /**
         * Initializes this object by wrapping the given OutputStream using the
         * specified encoding.
         */
        public void Initialize2(OutputStream OutputStream, String Encoding) {
            setObject(new BufferedWriter(new OutputStreamWriter(OutputStream, Charset.forName(Encoding)),
                    4096));
        }

        /**
         * Writes the given Text to the stream.
         */
        public void Write(String Text) throws IOException {
            getObject().write(Text);
        }

        /**
         * Writes the given Text to the stream followed by a new line character. null         Example:<code>
		 * 	Dim Writer As TextWriter
         *	Writer.Initialize(File.OpenOutput(File.DirDefaultExternal, "1.txt", False))
         *	Writer.WriteLine("This is the first line.")
         *	Writer.WriteLine("This is the second line.")
         *	Writer.Close </code>
         */
        public void WriteLine(String Text) throws IOException {
            getObject().write(Text + "\n");
        }

        /**
         * Writes each item in the list as a single line. Note that a value
         * containing CRLF will be saved as two lines (which will return two
         * item when read with ReadList). All values will be converted to
         * strings.
         */
        public void WriteList(List List) throws IOException {
            for (Object line : List.getObject()) {
                WriteLine(String.valueOf(line));
            }
        }

        /**
         * Closes the stream.
         */
        public void Close() throws IOException {
            getObject().close();
        }

        /**
         * Flushes any buffered data.
         */
        public void Flush() throws IOException {
            getObject().flush();
        }
    }

    /**
     * Reads text from the underlying stream.
     */
    @ShortName("TextReader")
    public static class TextReaderWrapper extends AbsObjectWrapper<BufferedReader> {

        /**
         * Initializes this object by wrapping the given InputStream using the
         * UTF8 encoding.
         */
        public void Initialize(InputStream InputStream) {
            setObject(new BufferedReader(new InputStreamReader(InputStream, Charset.forName("UTF8")),
                    4096));
        }

        /**
         * Initializes this object by wrapping the given InputStream using the
         * specified encoding.
         */
        public void Initialize2(InputStream InputStream, String Encoding) {
            setObject(new BufferedReader(new InputStreamReader(InputStream, Charset.forName(Encoding)),
                    4096));
        }

        /**
         * Reads the next line from the stream. The new line characters are not
         * returned. Returns Null if there are no more characters to read.
         *
         * Example:<code>
         *	Dim Reader As TextReader
         *	Reader.Initialize(File.OpenInput(File.InternalDir, "1.txt"))
         *	Dim line As String
         * 	line = Reader.ReadLine
         * 	Do While line <> Null Log(line) line = Reader.ReadLine Loop
         * Reader.Close</code>
         */
        public String ReadLine() throws IOException {
            return getObject().readLine();
        }

        /**
         * Reads characters from the stream and into the Buffer. Reads up to
         * Length characters and puts them in the Buffer starting as
         * StartOffset. Returns the actual number of characters read from the
         * stream. Returns -1 if there are no more characters available.
         */
        public int Read(char[] Buffer, int StartOffset, int Length) throws IOException {
            return getObject().read(Buffer, StartOffset, Length);
        }

        /**
         * Tests whether there is at least one character ready for reading
         * without blocking.
         */
        public boolean Ready() throws IOException {
            return getObject().ready();
        }

        /**
         * Reads all of the remaining text and closes the stream.
         */
        public String ReadAll() throws IOException {
            char[] buffer = new char[1024];
            StringBuilder sb = new StringBuilder(1024);
            int count;
            while ((count = Read(buffer, 0, buffer.length)) != -1) {
                if (count < buffer.length) {
                    sb.append(new String(buffer, 0, count));
                } else {
                    sb.append(buffer);
                }
            }
            Close();
            return sb.toString();
        }

        /**
         * Reads the remaining text and returns a List object filled with the
         * lines. Closes the stream when done.
         */
        public anywheresoftware.b4a.objects.collections.List ReadList() throws IOException {
            anywheresoftware.b4a.objects.collections.List List = new anywheresoftware.b4a.objects.collections.List();
            List.Initialize();
            String line;
            while ((line = ReadLine()) != null) {
                List.Add(line);
            }
            Close();
            return List;
        }

        /**
         * Skips the specified number of characters. Returns the actual number
         * of characters that were skipped (which may be less than the specified
         * value).
         */
        public int Skip(int NumberOfCharaceters) throws IOException {
            return (int) getObject().skip(NumberOfCharaceters);
        }

        public void Close() throws IOException {
            getObject().close();
        }

    }
}
