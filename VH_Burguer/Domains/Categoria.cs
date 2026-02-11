using System;
using System.Collections.Generic;

namespace VH_Burguer.Domains;

public partial class Categoria
{
    public int CategoriaID { get; set; }

    public string Nome { get; set; } = null!;

    public virtual ICollection<Produto> Produto { get; set; } = new List<Produto>();
}
