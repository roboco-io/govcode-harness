'use strict';
(() => {
  let token = '', current = null;
  const el = id => document.getElementById(id);
  const stateNames = {satisfied:'충족',unsatisfied:'보완 필요',review_required:'검토 필요',not_evaluated:'검사 필요',error:'확인 오류',not_due:'후속 단계',not_applicable:'승인 제외',stale:'새 검사 필요'};
  const labels = {total:'전체',applicable:'적용',not_applicable:'승인 제외',pending:'미확정',current:'현재 단계',not_due:'후속 단계'};
  const stageNames = {initiation:'착수',verification:'검증',planning:'계획',requirements:'요구 파악',design:'설계',implementation:'구현',testing:'시험',acceptance:'인수',operations:'운영'};
  async function api(path, body) {
    const response = await fetch(path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+token,...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
    const result = await response.json();
    if(!response.ok) throw new Error(result.error === 'REVIEW_SUBJECT_MISMATCH'?'자료가 바뀌었습니다. 새로 확인한 뒤 검토하세요.':result.error === 'SELF_APPROVAL'?'작성자는 자신의 산출물을 승인할 수 없습니다.':result.error === 'REVIEW_DUPLICATE'?'현재 자료의 검토가 이미 기록되어 있습니다.':'현재 자료나 접속 권한을 확인해 주세요.');
    return result;
  }
  function text(tag, value, className) { const node = document.createElement(tag);node.textContent=value;if(className)node.className=className;return node; }
  async function refresh() {
    const data = await api('/api/projects/current');current=data;
    el('login').hidden=true;el('project').hidden=false;
    el('scope').textContent='기관 '+data.tenant_id+' · 프로젝트 '+data.project_id;
    el('selection').textContent='선택한 변경본 '+data.commit_sha+' · 현재 단계 '+(stageNames[data.stage]||data.stage);
    el('counts').replaceChildren(...Object.entries(labels).map(([key,label])=>text('span',label+' '+data.counts[key])));
    el('rows').replaceChildren();el('requirement').replaceChildren();
    for(const row of data.requirements) {
      const id=row.requirement_ref.id, record=text('div','','record'), detail=document.createElement('div');
      detail.append(text('strong',id),text('p',stateNames[row.status]||'확인 필요'));
      for(const item of data.work_items.filter(item=>item.requirement_ref.id===id)) detail.append(text('p',item.instruction));
      if(row.status==='not_due')detail.append(text('p','승인된 후속 단계에서 다시 확인합니다.'));
      record.append(detail);el('rows').append(record);
      if(!row.review_refs.length && row.artifact_digests.length) {const option=text('option',id);option.value=id;el('requirement').append(option);}
    }
    el('review-panel').hidden=!data.roles.includes('approver');
    el('review-form').querySelector('button').disabled=!el('requirement').options.length;
    const passed=data.stage_gate && data.stage_gate.allowed===true && data.stage_gate.outcome==='allow';
    el('stage-summary').textContent=passed?'현재 단계의 검사·검토·증적 확인을 마쳤습니다. 후속 단계 요구는 별도로 남아 있습니다.':'현재 단계 확인이 필요합니다. 필요한 검사·검토·증적을 보완한 뒤 다시 확인하세요.';
    el('status').textContent=passed?'현재 단계 통과를 확인했습니다.':'현재 자료를 확인했습니다. 단계 통과 확인은 대기 중입니다.';
  }
  async function run(action) {try {await action();}catch(error){el('status').textContent=error.message;}}
  el('login-form').addEventListener('submit',event=>{event.preventDefault();token=el('token').value;el('token').value='';run(refresh);});
  el('refresh').addEventListener('click',()=>run(refresh));
  el('logout').addEventListener('click',()=>{token='';current=null;el('project').hidden=true;el('login').hidden=false;el('rows').replaceChildren();el('status').textContent='접속을 종료했습니다.';});
  el('review-form').addEventListener('submit',event=>{event.preventDefault();run(async()=>{await api('/api/projects/reviews',{requirement_id:el('requirement').value,decision:el('decision').value,reason_ref:el('reason').value,expected_subject_digest:current.subject_digest});el('reason').value='';await refresh();});});
})();
