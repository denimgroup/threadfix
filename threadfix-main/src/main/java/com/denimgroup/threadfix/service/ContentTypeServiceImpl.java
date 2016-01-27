////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.service;

import java.util.HashMap;
import java.util.Map;


public class ContentTypeServiceImpl implements ContentTypeService {
	private boolean strictWhiteList;
	private String defaultType;
	private static final Map<String, String> whiteList;
	private static final Map<String, String> blackList;
	private static final Map<String, String> transList;
	static{
		whiteList = new HashMap<>();
		blackList = new HashMap<>();
		transList = new HashMap<>();
		
		/*-----WHITE LIST-----*/
		whiteList.put("text/plain", "text/plain");
		whiteList.put("application/plain", "application/plain");
		whiteList.put("text/html", "text/html");
		whiteList.put("text/webviewhtml", "text/webviewhtml");
		whiteList.put("text/x-server-parsed-html", "text/x-server-parsed-html");
		whiteList.put("text/xml", "text/xml");
		whiteList.put("application/xml", "application/xml");
		whiteList.put("json", "json");
		whiteList.put("application/pdf","application/pdf");
		whiteList.put("image/x-jg", "image/x-jg");
		whiteList.put("image/bmp", "image/bmp");
		whiteList.put("image/x-windows-bmp", "image/x-windows-bmp");
		whiteList.put("image/vnd.dwg", "image/vnd.dwg");
		whiteList.put("image/x-dwg", "image/x-dwg");
		whiteList.put("image/fif", "image/fif");
		whiteList.put("image/florian", "image/florian");
		whiteList.put("image/vnd.fpx", "image/vnd.fpx");
		whiteList.put("image/vnd.net-fpx", "image/vnd.net-fpx");
		whiteList.put("image/g3fax", "image/g3fax");
		whiteList.put("image/gif", "image/gif");
		whiteList.put("image/x-icon", "image/x-icon");
		whiteList.put("image/ief", "image/ief");
		whiteList.put("image/ief", "image/ief");
		whiteList.put("image/jpeg", "image/jpeg");
		whiteList.put("image/pjpeg", "image/pjpeg");
		whiteList.put("image/x-jps", "image/x-jps");
		whiteList.put("image/jutvision", "image/jutvision");
		whiteList.put("image/vasa", "image/vasa");
		whiteList.put("image/naplps", "image/naplps");
		whiteList.put("image/x-niff", "image/x-niff");
		whiteList.put("image/x-portable-bitmap", "image/x-portable-bitmap");
		whiteList.put("image/x-pict", "image/x-pict");
		whiteList.put("image/x-pcx", "image/x-pcx");
		whiteList.put("image/x-portable-graymap", "image/x-portable-graymap");
		whiteList.put("image/x-portable-greymap", "image/x-portable-greymap");
		whiteList.put("image/pict", "image/pict");
		whiteList.put("image/x-xpixmap", "image/x-xpixmap");
		whiteList.put("image/png", "image/png");
		whiteList.put("image/x-portable-anymap", "image/x-portable-anymap");
		whiteList.put("image/x-portable-pixmap", "image/x-portable-pixmap");
		whiteList.put("image/x-quicktime", "image/x-quicktime");
		whiteList.put("image/cmu-raster", "image/cmu-raster");
		whiteList.put("image/x-cmu-raster", "image/x-cmu-raster");
		whiteList.put("image/vnd.rn-realflash", "image/vnd.rn-realflash");
		whiteList.put("image/x-rgb", "image/x-rgb");
		whiteList.put("image/vnd.rn-realpix", "image/vnd.rn-realpix");
		whiteList.put("image/vnd.dwg", "image/vnd.dwg");
		whiteList.put("image/x-dwg", "image/x-dwg");
		whiteList.put("image/tiff", "image/tiff");
		whiteList.put("image/x-tiff", "image/x-tiff");
		whiteList.put("image/florian", "image/florian");
		whiteList.put("image/vnd.wap.wbmp", "image/vnd.wap.wbmp");
		whiteList.put("image/x-xbitmap", "image/x-xbitmap");
		whiteList.put("image/x-xbm", "image/x-xbm");
		whiteList.put("image/xbm", "image/xbm");
		whiteList.put("image/vnd.xiff", "image/vnd.xiff");
		whiteList.put("image/x-xpixmap", "image/x-xpixmap");
		whiteList.put("image/xpm", "image/xpm");
		whiteList.put("image/x-xwd", "image/x-xwd");
		whiteList.put("image/x-xwindowdump", "image/x-xwindowdump");
		/*-----BLACK LIST-----*/

		/*-----TRANSLATION LIST-----*/
		transList.put("application/plain", "text/plain");
		transList.put("text/html", "text/plain");
		transList.put("text/webviewhtml", "text/plain");
		transList.put("text/x-server-parsed-html", "text/plain");
		transList.put("application/xml", "text/xml");
		transList.put("json", "text/plain");

		
	}
	
	public ContentTypeServiceImpl() {
		strictWhiteList = false;
		defaultType = "application/octet-stream";
	}
	
	@Override
	public boolean isWhiteList(String contentType){
		return whiteList.containsKey(contentType);
	}
	@Override
	public boolean isBlackList(String contentType){
		return blackList.containsKey(contentType);
	}
	@Override
	public boolean isStrictWhiteList(){
		return strictWhiteList;
	}

	@Override
	public String translateContentType(String contentType){
		if(!whiteList.containsKey(contentType) && !transList.containsKey(contentType)){
			return defaultType;
		}
		
		if(transList.containsKey(contentType)){
			return transList.get(contentType);
		}
		
		return contentType;
	}
	@Override
	public boolean isValidUpload(String contentType){
		if (isWhiteList(contentType)){
			return true;
		}else if(!isStrictWhiteList() && !isBlackList(contentType)){
			return true;
		}
		
		return false;
	}
	
	@Override
	public String getDefaultType(){
		return defaultType;
	}
	
}
