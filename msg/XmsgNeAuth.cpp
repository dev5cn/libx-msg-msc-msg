/*
  Copyright 2019 www.dev5.cn, Inc. dev5@qq.com
 
  This file is part of X-MSG-IM.
 
  X-MSG-IM is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  X-MSG-IM is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 
  You should have received a copy of the GNU Affero General Public License
  along with X-MSG-IM.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "XmsgNeAuth.h"

XmsgNeAuth::XmsgNeAuth()
{

}

void XmsgNeAuth::handle4ne(shared_ptr<XscChannel> channel, SptrXitp trans, shared_ptr<XmsgNeAuthReq> req)
{
	if (req->neg().empty() || req->cgt().empty() || req->salt().empty() || req->sign().empty())
	{
		trans->endDesc(RET_FORMAT_ERROR, "request format error: %s", req->ShortDebugString().c_str());
		return;
	}
	SptrCgt cgt = ChannelGlobalTitle::parse(req->cgt());
	if (cgt == nullptr)
	{
		trans->endDesc(RET_FORMAT_ERROR, "channel global title format error, req: %s", req->ShortDebugString().c_str());
		return;
	}
	if (cgt->domain != XmsgMscCfg::instance()->cgt->domain) 
	{
		trans->endDesc(RET_FORBIDDEN, "foreign service");
		return;
	}
	if (cgt->hlr == XmsgMscCfg::instance()->cgt->hlr) 
	{
		trans->endDesc(RET_FORBIDDEN, "your channel global title config error: %s", cgt->toString().c_str());
		return;
	}
	shared_ptr<XmsgMscCfgXmsgNe> xmsgNe = XmsgNeAuth::findXmsgNeCfg(req->cgt());
	if (xmsgNe == nullptr)
	{
		trans->endDesc(RET_USR_OR_PASSWORD_ERROR, "cgt or password error");
		return;
	}
	if (Crypto::sha256ToHexStrLowerCase(xmsgNe->cgt() + req->salt() + xmsgNe->pwd()) != req->sign()) 
	{
		trans->endDesc(RET_FORBIDDEN, "sign error");
		return;
	}
	string domainHlr = cgt->domain + "." + cgt->hlr;
	LOG_INFO("x-msg network element auth successful, domain-hlr: %s, req: %s", domainHlr.c_str(), req->ShortDebugString().c_str())
	auto group = XmsgNeGroupMgr::instance()->findByGroupName(domainHlr); 
	if (group == nullptr)
		group.reset(new XmsgNeGroup(domainHlr, (XmsgNeRedundantType) req->redundant()));
	group = XmsgNeGroupMgr::instance()->addOrGet(group); 
	shared_ptr<XmsgNeUsr> nu(new XmsgNeUsr(req->neg() , req->cgt(), trans->channel));
	trans->channel->setXscUsr(nu);
	auto old = group->add(nu);
	group = XmsgNeGroupMgr::instance()->findByGroupName(req->neg()); 
	if (group == nullptr)
		group.reset(new XmsgNeGroup(req->neg(), (XmsgNeRedundantType) req->redundant()));
	group = XmsgNeGroupMgr::instance()->addOrGet(group); 
	group->add(nu);
	XmsgNeUsr::pubEvnEstab(nu); 
	shared_ptr<XmsgNeAuthRsp> rsp(new XmsgNeAuthRsp());
	rsp->set_cgt(XmsgMscCfg::instance()->cfgPb->cgt());
	trans->end(rsp);
	if (old == nullptr)
		return;
	LOG_WARN("have old network element on line, we will kick it, ne: %s", old->toString().c_str())
	auto c = old->channel;
	c->future([c]
	{
		c->close();
	});
}

void XmsgNeAuth::handle4msc(shared_ptr<XscChannel> channel, SptrXitp trans, shared_ptr<XmsgNeAuthReq> req)
{
	if (req->cgt().empty() || req->salt().empty() || req->sign().empty())
	{
		trans->endDesc(RET_FORMAT_ERROR, "request format error: %s", req->ShortDebugString().c_str());
		return;
	}
	SptrCgt cgt = ChannelGlobalTitle::parse(req->cgt());
	if (cgt == nullptr)
	{
		trans->endDesc(RET_FORMAT_ERROR, "channel global title format error, req: %s", req->ShortDebugString().c_str());
		return;
	}
	shared_ptr<XmsgMscCfgXmsgNe> msc = XmsgNeAuth::findXmsgMscCfg(req->cgt());
	if (msc == nullptr)
	{
		trans->endDesc(RET_USR_OR_PASSWORD_ERROR, "cgt or password error");
		return;
	}
	if (Crypto::sha256ToHexStrLowerCase(msc->cgt() + req->salt() + msc->pwd()) != req->sign()) 
	{
		trans->endDesc(RET_FORBIDDEN, "sign error");
		return;
	}
	string node;
	if (!XmsgMscMgr::instance()->isSubordinate(cgt, node)) 
	{
		trans->endDesc(RET_FORBIDDEN, "it`s not subordinate domain");
		return;
	}
	shared_ptr<XmsgMscSubordinate> sub(new XmsgMscSubordinate(node, cgt, trans->channel));
	trans->channel->setXscUsr(sub);
	auto old = XmsgMscMgr::instance()->addSubordinate(node, sub);
	LOG_INFO("x-msg-msc auth successful, node: %s, req: %s", node.c_str(), req->ShortDebugString().c_str())
	shared_ptr<XmsgNeAuthRsp> rsp(new XmsgNeAuthRsp());
	rsp->set_cgt(XmsgMscCfg::instance()->cfgPb->cgt());
	trans->end(rsp);
	if (old == nullptr)
		return;
	LOG_WARN("have old subordinate x-msc-msc on line, we will kick it, msc: %s", old->toString().c_str())
	auto c = old->channel;
	c->future([c]
	{
		c->close();
	});
}

shared_ptr<XmsgMscCfgXmsgNe> XmsgNeAuth::findXmsgMscCfg(const string& cgt)
{
	for (int i = 0; i < XmsgMscCfg::instance()->cfgPb->subordinate_size(); ++i)
	{
		auto subordinate = XmsgMscCfg::instance()->cfgPb->subordinate(i);
		if (subordinate.cgt() != cgt)
			continue;
		shared_ptr<XmsgMscCfgXmsgNe> msc(new XmsgMscCfgXmsgNe());
		msc->CopyFrom(subordinate);
		return msc;
	}
	return nullptr;
}

shared_ptr<XmsgMscCfgXmsgNe> XmsgNeAuth::findXmsgNeCfg(const string& cgt)
{
	for (int i = 0; i < XmsgMscCfg::instance()->cfgPb->n2h_size(); ++i) 
	{
		auto& ne = XmsgMscCfg::instance()->cfgPb->n2h(i);
		if (ne.cgt() != cgt)
			continue;
		shared_ptr<XmsgMscCfgXmsgNe> cfgXmsgNe(new XmsgMscCfgXmsgNe());
		cfgXmsgNe->CopyFrom(ne);
		return cfgXmsgNe;
	}
	return nullptr;
}

XmsgNeAuth::~XmsgNeAuth()
{

}
