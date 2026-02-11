using System;
using System.Collections.Generic;

namespace VH_Burguer.Domains;

public partial class ProdutoPromocao
{
    public int PromocaoID { get; set; }

    public int ProdutoID { get; set; }

    public decimal PrecoAtual { get; set; }

    public virtual Produto Produto { get; set; } = null!;

    public virtual Promocao Promocao { get; set; } = null!;
}
