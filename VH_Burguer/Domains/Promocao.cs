using System;
using System.Collections.Generic;

namespace VH_Burguer.Domains;

public partial class Promocao
{
    public int PromocaoID { get; set; }

    public string Nome { get; set; } = null!;

    public DateTime DataExpiracao { get; set; }

    public bool StatusPromocao { get; set; }

    public virtual ICollection<ProdutoPromocao> ProdutoPromocao { get; set; } = new List<ProdutoPromocao>();
}
