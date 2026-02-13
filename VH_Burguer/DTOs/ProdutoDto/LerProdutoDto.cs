namespace VH_Burguer.DTOs.ProdutoDto
{
    public class LerProdutoDto
    {
        public int ProdutoID { get; set; }
        public string Nome { get; set; } = null!;
        public decimal Preco { get; set; }
        public string Descricao { get; set; } = null!;
        public bool? StatusProduto { get; set; }


        public List<int> CategoriaIds { get; set; } = new();
        public List<string> Categorias { get; set; } = new();

        public int? UsuarioID { get; set; }
        public string? UsuarioNome { get; set; }
        public string? UsuarioEmail { get; set; }
    }    
}
