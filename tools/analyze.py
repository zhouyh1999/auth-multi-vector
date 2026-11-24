import matplotlib
matplotlib.use('Agg')
from matplotlib import pyplot as plt, ticker
from audit_visit import OUT, METHODS, SCOPES

def render(stats,n):
    plt.rcParams.update({'font.sans-serif':['DejaVu Sans'],
        'svg.fonttype':'path','axes.unicode_minus':False})
    fig,axes=plt.subplots(2,2,figsize=(13.4,8.4))
    fig.subplots_adjust(left=.152,right=.868,top=.80,bottom=.16,wspace=.72,hspace=.62)
    title='First-visit authenticated retrieval latency'
    coverage=f'First {n:,} queries in frozen order'
    fig.text(.036,.955,title,fontsize=23,fontweight='bold',va='top',color='#19313c')
    fig.text(.036,.878,f'LoTTE · ColBERTv2  |  {coverage}  |  Query-weighted mean and P10–P90',fontsize=11.5,color='#445b65')
    palette=('#526f81','#ab643f','#b38126','#16785e')
    lookup={(r['policy'],r['stage']):r for r in stats}
    for ax,stage,title in zip(axes.flat,SCOPES,("Coarse codebook", "Fine codebook", "Candidate reranking", "Full query")):
        use=[lookup[m,stage] for m in METHODS]
        lo=min(min(r['p10_ms'],r['mean_ms']) for r in use)*.82
        hi=max(max(r['p90_ms'],r['mean_ms']) for r in use)*1.18
        ticks=[b*10**v for v in range(-2,6) for b in (1,2,5) if lo<=b*10**v<=hi]
        if len(ticks)<3:ticks=sorted(ticks+[b*10**v for v in range(-2,6) for b in (3,6) if lo<=b*10**v<=hi])
        ax.set_xscale('log');ax.set_xlim(lo,hi);ax.set_ylim(3.45,-.55)
        ax.set_yticks(range(4),("Raw", "VIDA per token", "VIDA batched", "Block"));ax.tick_params(axis='y',length=0,pad=8,labelsize=10)
        ax.xaxis.set_major_locator(ticker.FixedLocator(ticks));ax.xaxis.set_minor_locator(ticker.NullLocator())
        ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x,_:f'{x:,.0f}'))
        ax.tick_params(axis='x',colors='#536572',labelsize=9)
        ax.grid(axis='x',color='#dae3e6',linewidth=.8);ax.set_axisbelow(True)
        for side in ('left','top','right'):ax.spines[side].set_visible(False)
        ax.spines['bottom'].set_color('#bfced1')
        ax.set_title(title,loc='left',fontsize=15.5,fontweight='bold',color='#19313c',pad=11)
        ax.text(1.27,1.02,'Mean (ms)',transform=ax.transAxes,ha='right',va='bottom',fontsize=9,color='#53646d')
        for j,(r,col) in enumerate(zip(use,palette)):
            endpoints=(r['p10_ms'],r['p90_ms'])
            ax.axhline(j,color='#e9eef0',linewidth=.65,zorder=0)
            ax.hlines(j,*endpoints,color=col,linewidth=2);ax.vlines(endpoints,j-.08,j+.08,color=col,linewidth=1.2)
            ax.scatter(r['mean_ms'],j,s=46,color=col,zorder=3)
            ax.text(1.27,j,f"{r['mean_ms']:,.1f}",transform=ax.get_yaxis_transform(),ha='right',va='center',
                fontsize=11,color=col,fontweight='bold' if j==3 else 'normal')
        ax.set_xlabel('Latency (ms, log scale)',fontsize=9.4,color='#53646d')
    foot=('Each request opens a fresh TLS connection. Per-query latency is the median of five formal measurements.',
          'Full queries are measured independently. Manifest retrieval was measured across hosts. Request and VO transfer assume 300 Mbps and zero additional RTT.')
    fig.text(.036,.083,foot[0],fontsize=10,color='#344f5c')
    fig.text(.036,.048,foot[1],fontsize=9.3,color='#51656c')
    output=OUT/'latency-first-visit'
    fig.savefig(output.with_suffix('.png'),dpi=180);fig.savefig(output.with_suffix('.svg'));plt.close(fig)

