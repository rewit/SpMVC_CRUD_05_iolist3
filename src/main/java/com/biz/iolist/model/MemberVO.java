package com.biz.iolist.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class MemberVO {

	
	private String m_userid;	//varchar2(15 byte)
	private String m_password;	//	nvarchar2(64 char)
	private String m_name;	//	nvarchar2(30 char)
	private String m_email;	//	varchar2(25 byte)
	private String m_tel;	//	varchar2(20 byte)
	private String m_role;	//	varchar2(5 byte)
}
